#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#include <ntifs.h>

#pragma warning(push)
#pragma warning(disable:4201)
#include <fwpsk.h>
#pragma warning(pop)
#include <fwpmk.h>
#include <guiddef.h>
#include <rpc.h>
#include <wdmsec.h>

#include "WfpProtocol.h"

#define PF_WFP_POOL_TAG 'pFrP'
#define PF_WFP_PENDING_TIMEOUT_100NS (5LL * 10LL * 1000LL * 1000LL)

typedef struct _PF_WFP_PENDING_EVENT
{
    LIST_ENTRY ListEntry;
    PF_WFP_FLOW_EVENT Event;
    HANDLE CompletionContext;
    LARGE_INTEGER QueuedAt;
    BOOLEAN Delivered;
    NET_BUFFER_LIST* NetBufferList;
    UINT64 EndpointHandle;
    COMPARTMENT_ID CompartmentId;
    ADDRESS_FAMILY AddressFamily;
    UINT8 RemoteAddress[PF_WFP_MAX_ADDRESS_BYTES];
    SCOPE_ID RemoteScopeId;
    WSACMSGHDR* ControlData;
    ULONG ControlDataLength;
} PF_WFP_PENDING_EVENT, *PPF_WFP_PENDING_EVENT;

static PDEVICE_OBJECT gDeviceObject;
static HANDLE gEngineHandle;
static UNICODE_STRING gDosDeviceName;
static UINT32 gCalloutIdV4;
static UINT32 gCalloutIdV6;
static LIST_ENTRY gPendingList;
static KSPIN_LOCK gPendingLock;
static KEVENT gEventAvailable;
static KEVENT gReaperStopEvent;
static HANDLE gReaperThreadHandle;
static PVOID gReaperThreadObject;
static LONG gConnectedClients;
static LONG gPendingCount;
static LONG64 gNextEventId;
static volatile LONG gUnloading;
static HANDLE gInjectionHandleV4;
static HANDLE gInjectionHandleV6;

static const GUID PF_WFP_PROVIDER =
{ 0x62c0a0a1, 0x9d00, 0x4d36, { 0x98, 0xa1, 0x73, 0x4b, 0xf0, 0x0d, 0x13, 0x61 } };

static const GUID PF_WFP_SUBLAYER =
{ 0x62c0a0a2, 0x9d00, 0x4d36, { 0x98, 0xa1, 0x73, 0x4b, 0xf0, 0x0d, 0x13, 0x61 } };

static const GUID PF_WFP_CALLOUT_V4 =
{ 0x62c0a0a3, 0x9d00, 0x4d36, { 0x98, 0xa1, 0x73, 0x4b, 0xf0, 0x0d, 0x13, 0x61 } };

static const GUID PF_WFP_CALLOUT_V6 =
{ 0x62c0a0a4, 0x9d00, 0x4d36, { 0x98, 0xa1, 0x73, 0x4b, 0xf0, 0x0d, 0x13, 0x61 } };

static VOID
PfWfpFreePending(_Inout_ PPF_WFP_PENDING_EVENT Entry)
{
    if (Entry->NetBufferList != NULL)
    {
        FwpsDereferenceNetBufferList(Entry->NetBufferList, FALSE);
        Entry->NetBufferList = NULL;
    }
    if (Entry->ControlData != NULL)
    {
        ExFreePoolWithTag(Entry->ControlData, PF_WFP_POOL_TAG);
        Entry->ControlData = NULL;
    }

    ExFreePoolWithTag(Entry, PF_WFP_POOL_TAG);
}

static VOID NTAPI
PfWfpInjectComplete(
    _In_ void* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel)
{
    UNREFERENCED_PARAMETER(dispatchLevel);
    FwpsFreeCloneNetBufferList(netBufferList, 0);
    PfWfpFreePending((PPF_WFP_PENDING_EVENT)context);
}

static VOID
PfWfpInjectUdpEvent(_Inout_ PPF_WFP_PENDING_EVENT Entry)
{
    NET_BUFFER_LIST* clonedNetBufferList = NULL;
    FWPS_TRANSPORT_SEND_PARAMS0 sendArgs = { 0 };
    HANDLE injectionHandle;
    NTSTATUS status;

    if (Entry->NetBufferList == NULL
        || Entry->EndpointHandle == 0
        || Entry->AddressFamily == AF_UNSPEC)
    {
        PfWfpFreePending(Entry);
        return;
    }

    status = FwpsAllocateCloneNetBufferList(
        Entry->NetBufferList,
        NULL,
        NULL,
        0,
        &clonedNetBufferList);
    FwpsDereferenceNetBufferList(Entry->NetBufferList, FALSE);
    Entry->NetBufferList = NULL;
    if (!NT_SUCCESS(status) || clonedNetBufferList == NULL)
    {
        PfWfpFreePending(Entry);
        return;
    }

    sendArgs.remoteAddress = Entry->RemoteAddress;
    sendArgs.remoteScopeId = Entry->RemoteScopeId;
    sendArgs.controlData = Entry->ControlData;
    sendArgs.controlDataLength = Entry->ControlDataLength;
    injectionHandle = Entry->AddressFamily == AF_INET
        ? gInjectionHandleV4
        : gInjectionHandleV6;

    if (injectionHandle == NULL)
    {
        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
        PfWfpFreePending(Entry);
        return;
    }

    status = FwpsInjectTransportSendAsync0(
        injectionHandle,
        NULL,
        Entry->EndpointHandle,
        0,
        &sendArgs,
        Entry->AddressFamily,
        Entry->CompartmentId,
        clonedNetBufferList,
        PfWfpInjectComplete,
        Entry);
    if (!NT_SUCCESS(status))
    {
        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
        PfWfpFreePending(Entry);
    }
}

static VOID
PfWfpCompletePendingEvent(_Inout_ PPF_WFP_PENDING_EVENT Entry)
{
    if (Entry->CompletionContext != NULL)
    {
        FwpsCompleteOperation0(Entry->CompletionContext, NULL);
        Entry->CompletionContext = NULL;
    }

    if (Entry->NetBufferList != NULL && !gUnloading)
    {
        PfWfpInjectUdpEvent(Entry);
        return;
    }

    PfWfpFreePending(Entry);
}

static VOID
PfWfpPermitAllPending(VOID)
{
    LIST_ENTRY expired;
    KLOCK_QUEUE_HANDLE lockHandle;

    InitializeListHead(&expired);

    KeAcquireInStackQueuedSpinLock(&gPendingLock, &lockHandle);
    while (!IsListEmpty(&gPendingList))
    {
        PLIST_ENTRY entry = RemoveHeadList(&gPendingList);
        InsertTailList(&expired, entry);
        InterlockedDecrement(&gPendingCount);
    }
    KeClearEvent(&gEventAvailable);
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    while (!IsListEmpty(&expired))
    {
        PLIST_ENTRY entry = RemoveHeadList(&expired);
        PPF_WFP_PENDING_EVENT pending = CONTAINING_RECORD(entry, PF_WFP_PENDING_EVENT, ListEntry);
        PfWfpCompletePendingEvent(pending);
    }
}

static VOID
PfWfpExpirePending(VOID)
{
    LARGE_INTEGER now;
    LIST_ENTRY expired;
    KLOCK_QUEUE_HANDLE lockHandle;

    InitializeListHead(&expired);
    KeQuerySystemTimePrecise(&now);

    KeAcquireInStackQueuedSpinLock(&gPendingLock, &lockHandle);
    for (PLIST_ENTRY entry = gPendingList.Flink; entry != &gPendingList;)
    {
        PLIST_ENTRY next = entry->Flink;
        PPF_WFP_PENDING_EVENT pending = CONTAINING_RECORD(entry, PF_WFP_PENDING_EVENT, ListEntry);
        if ((now.QuadPart - pending->QueuedAt.QuadPart) < PF_WFP_PENDING_TIMEOUT_100NS)
        {
            entry = next;
            continue;
        }

        RemoveEntryList(entry);
        InsertTailList(&expired, entry);
        InterlockedDecrement(&gPendingCount);
        entry = next;
    }
    if (IsListEmpty(&gPendingList))
    {
        KeClearEvent(&gEventAvailable);
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    while (!IsListEmpty(&expired))
    {
        PLIST_ENTRY entry = RemoveHeadList(&expired);
        PPF_WFP_PENDING_EVENT pending = CONTAINING_RECORD(entry, PF_WFP_PENDING_EVENT, ListEntry);
        PfWfpCompletePendingEvent(pending);
    }
}

static VOID
PfWfpReaperThread(_In_ PVOID context)
{
    UNREFERENCED_PARAMETER(context);

    for (;;)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000000LL;

        if (KeWaitForSingleObject(
                &gReaperStopEvent,
                Executive,
                KernelMode,
                FALSE,
                &timeout) == STATUS_SUCCESS)
        {
            break;
        }

        PfWfpExpirePending();
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static BOOLEAN
PfWfpIsReauthorize(_In_ const FWPS_INCOMING_VALUES0* inFixedValues)
{
    UINT32 flagsIndex;

    switch (inFixedValues->layerId)
    {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        flagsIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        flagsIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
        break;
    default:
        return FALSE;
    }

    return (inFixedValues->incomingValue[flagsIndex].value.uint32
        & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0;
}

static BOOLEAN
PfWfpIsInjected(
    _In_ UINT16 layerId,
    _In_opt_ void* layerData)
{
    FWPS_PACKET_INJECTION_STATE state;
    HANDLE injectionHandle;

    if (layerData == NULL)
    {
        return FALSE;
    }

    injectionHandle = layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4
        ? gInjectionHandleV4
        : gInjectionHandleV6;
    if (injectionHandle == NULL)
    {
        return FALSE;
    }

    state = FwpsQueryPacketInjectionState(injectionHandle, layerData, NULL);
    return state == FWPS_PACKET_INJECTED_BY_SELF
        || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF;
}

static VOID
PfWfpFillEvent(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_ PF_WFP_FLOW_EVENT* event)
{
    UINT localAddressIndex;
    UINT remoteAddressIndex;
    UINT localPortIndex;
    UINT remotePortIndex;
    UINT protocolIndex;

    RtlZeroMemory(event, sizeof(*event));
    event->EventId = (UINT64)InterlockedIncrement64(&gNextEventId);
    event->ProcessId = FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)
        ? inMetaValues->processId
        : 0;

    switch (inFixedValues->layerId)
    {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        event->AddressFamily = AF_INET;
        localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
        remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
        localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
        remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
        protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;

        {
            UINT32 localAddress = RtlUlongByteSwap(
                inFixedValues->incomingValue[localAddressIndex].value.uint32);
            UINT32 remoteAddress = RtlUlongByteSwap(
                inFixedValues->incomingValue[remoteAddressIndex].value.uint32);
            RtlCopyMemory(event->LocalAddress, &localAddress, sizeof(localAddress));
            RtlCopyMemory(event->RemoteAddress, &remoteAddress, sizeof(remoteAddress));
        }
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        event->AddressFamily = AF_INET6;
        localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
        remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
        localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
        remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
        protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;

        RtlCopyMemory(
            event->LocalAddress,
            inFixedValues->incomingValue[localAddressIndex].value.byteArray16,
            sizeof(event->LocalAddress));
        RtlCopyMemory(
            event->RemoteAddress,
            inFixedValues->incomingValue[remoteAddressIndex].value.byteArray16,
            sizeof(event->RemoteAddress));
        break;
    default:
        return;
    }

    event->LocalPort = RtlUshortByteSwap(
        inFixedValues->incomingValue[localPortIndex].value.uint16);
    event->RemotePort = RtlUshortByteSwap(
        inFixedValues->incomingValue[remotePortIndex].value.uint16);
    event->Protocol = inFixedValues->incomingValue[protocolIndex].value.uint8;

    switch (inFixedValues->layerId)
    {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        event->InterfaceIndex =
            inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX].value.uint32;
        event->SubInterfaceIndex =
            inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_SUB_INTERFACE_INDEX].value.uint32;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        event->InterfaceIndex =
            inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_INDEX].value.uint32;
        event->SubInterfaceIndex =
            inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_SUB_INTERFACE_INDEX].value.uint32;
        break;
    default:
        break;
    }
}

static VOID NTAPI
PfWfpClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    PPF_WFP_PENDING_EVENT pending;
    KLOCK_QUEUE_HANDLE lockHandle;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }

    if (PfWfpIsReauthorize(inFixedValues)
        || InterlockedCompareExchange(&gConnectedClients, 0, 0) <= 0
        || PfWfpIsInjected(inFixedValues->layerId, layerData)
        || !FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPLETION_HANDLE))
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    pending = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*pending), PF_WFP_POOL_TAG);
    if (pending == NULL)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    RtlZeroMemory(pending, sizeof(*pending));
    PfWfpFillEvent(inFixedValues, inMetaValues, &pending->Event);

    if (pending->Event.Protocol == IPPROTO_UDP)
    {
        if (layerData == NULL)
        {
            PfWfpFreePending(pending);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            return;
        }

        pending->AddressFamily = (ADDRESS_FAMILY)pending->Event.AddressFamily;
        pending->NetBufferList = (NET_BUFFER_LIST*)layerData;
        FwpsReferenceNetBufferList(pending->NetBufferList, TRUE);
        RtlCopyMemory(
            pending->RemoteAddress,
            pending->Event.RemoteAddress,
            pending->AddressFamily == AF_INET ? 4 : 16);

        if (FWPS_IS_METADATA_FIELD_PRESENT(
                inMetaValues,
                FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE))
        {
            pending->EndpointHandle = inMetaValues->transportEndpointHandle;
        }
        if (FWPS_IS_METADATA_FIELD_PRESENT(
                inMetaValues,
                FWPS_METADATA_FIELD_COMPARTMENT_ID))
        {
            pending->CompartmentId = inMetaValues->compartmentId;
        }
        if (FWPS_IS_METADATA_FIELD_PRESENT(
                inMetaValues,
                FWPS_METADATA_FIELD_REMOTE_SCOPE_ID))
        {
            pending->RemoteScopeId = inMetaValues->remoteScopeId;
        }
        if (FWPS_IS_METADATA_FIELD_PRESENT(
                inMetaValues,
                FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA)
            && inMetaValues->controlDataLength > 0)
        {
            pending->ControlData = ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                inMetaValues->controlDataLength,
                PF_WFP_POOL_TAG);
            if (pending->ControlData == NULL)
            {
                PfWfpFreePending(pending);
                classifyOut->actionType = FWP_ACTION_PERMIT;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
                return;
            }

            RtlCopyMemory(
                pending->ControlData,
                inMetaValues->controlData,
                inMetaValues->controlDataLength);
            pending->ControlDataLength = inMetaValues->controlDataLength;
        }
    }

    status = FwpsPendOperation0(inMetaValues->completionHandle, &pending->CompletionContext);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(pending, PF_WFP_POOL_TAG);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    pending->QueuedAt.QuadPart = 0;
    KeQuerySystemTimePrecise(&pending->QueuedAt);

    KeAcquireInStackQueuedSpinLock(&gPendingLock, &lockHandle);
    if (gUnloading
        || gPendingCount >= PF_WFP_MAX_EVENT_QUEUE
        || InterlockedCompareExchange(&gConnectedClients, 0, 0) <= 0)
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        PfWfpCompletePendingEvent(pending);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    InsertTailList(&gPendingList, &pending->ListEntry);
    InterlockedIncrement(&gPendingCount);
    KeSetEvent(&gEventAvailable, IO_NO_INCREMENT, FALSE);
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}

static NTSTATUS NTAPI
PfWfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ const FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static NTSTATUS
PfWfpAddCallout(
    _In_ const GUID* layerKey,
    _In_ const GUID* calloutKey,
    _In_ const wchar_t* name,
    _Out_ UINT32* calloutId)
{
    NTSTATUS status;
    FWPS_CALLOUT0 callout = { 0 };
    FWPM_CALLOUT0 calloutDefinition = { 0 };
    FWPM_FILTER0 filter = { 0 };

    callout.calloutKey = *calloutKey;
    callout.classifyFn = PfWfpClassify;
    callout.notifyFn = PfWfpNotify;

    status = FwpsCalloutRegister0(gDeviceObject, &callout, calloutId);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    calloutDefinition.calloutKey = *calloutKey;
    calloutDefinition.displayData.name = (wchar_t*)name;
    calloutDefinition.displayData.description = (wchar_t*)name;
    calloutDefinition.applicableLayer = *layerKey;

    status = FwpmCalloutAdd0(gEngineHandle, &calloutDefinition, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    filter.layerKey = *layerKey;
    filter.displayData.name = (wchar_t*)name;
    filter.displayData.description = (wchar_t*)name;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *calloutKey;
    filter.subLayerKey = PF_WFP_SUBLAYER;
    filter.weight.type = FWP_EMPTY;

    return FwpmFilterAdd0(gEngineHandle, &filter, NULL, NULL);
}

static NTSTATUS
PfWfpInitializeCallouts(VOID)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { 0 };
    FWPM_SUBLAYER0 sublayer = { 0 };

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngineHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = FwpmTransactionBegin0(gEngineHandle, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    sublayer.subLayerKey = PF_WFP_SUBLAYER;
    sublayer.displayData.name = L"ProxiFyre WFP Classifier";
    sublayer.displayData.description = L"Classifies target application flows before WinpkFilter redirection.";
    sublayer.weight = 0x100;

    status = FwpmSubLayerAdd0(gEngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
    {
        FwpmTransactionAbort0(gEngineHandle);
        return status;
    }

    status = PfWfpAddCallout(
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &PF_WFP_CALLOUT_V4,
        L"ProxiFyre WFP IPv4 connect classifier",
        &gCalloutIdV4);
    if (!NT_SUCCESS(status))
    {
        FwpmTransactionAbort0(gEngineHandle);
        return status;
    }

    status = PfWfpAddCallout(
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &PF_WFP_CALLOUT_V6,
        L"ProxiFyre WFP IPv6 connect classifier",
        &gCalloutIdV6);
    if (!NT_SUCCESS(status))
    {
        FwpmTransactionAbort0(gEngineHandle);
        return status;
    }

    return FwpmTransactionCommit0(gEngineHandle);
}

static NTSTATUS
PfWfpDispatchCreate(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);
    InterlockedIncrement(&gConnectedClients);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
PfWfpDispatchCleanup(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    if (InterlockedDecrement(&gConnectedClients) <= 0)
    {
        InterlockedExchange(&gConnectedClients, 0);
        PfWfpPermitAllPending();
    }

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
PfWfpDispatchClose(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
PfWfpDispatchIoctl(_In_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG information = 0;
    PVOID systemBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    UNREFERENCED_PARAMETER(deviceObject);

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case PF_WFP_IOCTL_GET_EVENT:
        if (systemBuffer == NULL || outputLength < sizeof(PF_WFP_FLOW_EVENT))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -10000000LL;

            for (;;)
            {
                NTSTATUS waitStatus = KeWaitForSingleObject(
                    &gEventAvailable,
                    Executive,
                    KernelMode,
                    FALSE,
                    &timeout);
                KLOCK_QUEUE_HANDLE lockHandle;
                PPF_WFP_PENDING_EVENT found = NULL;

                if (waitStatus == STATUS_TIMEOUT)
                {
                    status = STATUS_TIMEOUT;
                    break;
                }

                KeAcquireInStackQueuedSpinLock(&gPendingLock, &lockHandle);
                for (PLIST_ENTRY entry = gPendingList.Flink;
                     entry != &gPendingList;
                     entry = entry->Flink)
                {
                    PPF_WFP_PENDING_EVENT pending =
                        CONTAINING_RECORD(entry, PF_WFP_PENDING_EVENT, ListEntry);
                    if (!pending->Delivered)
                    {
                        found = pending;
                        break;
                    }
                }

                if (found != NULL)
                {
                    found->Delivered = TRUE;
                    RtlCopyMemory(systemBuffer, &found->Event, sizeof(found->Event));
                    information = sizeof(found->Event);
                    status = STATUS_SUCCESS;
                }
                else
                {
                    KeClearEvent(&gEventAvailable);
                }
                KeReleaseInStackQueuedSpinLock(&lockHandle);

                if (found != NULL)
                {
                    break;
                }
            }
        }
        break;

    case PF_WFP_IOCTL_COMPLETE_EVENT:
        if (systemBuffer == NULL || inputLength < sizeof(PF_WFP_VERDICT))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        {
            PF_WFP_VERDICT* verdict = (PF_WFP_VERDICT*)systemBuffer;
            PPF_WFP_PENDING_EVENT found = NULL;
            KLOCK_QUEUE_HANDLE lockHandle;

            KeAcquireInStackQueuedSpinLock(&gPendingLock, &lockHandle);
            for (PLIST_ENTRY entry = gPendingList.Flink;
                 entry != &gPendingList;
                 entry = entry->Flink)
            {
                PPF_WFP_PENDING_EVENT pending =
                    CONTAINING_RECORD(entry, PF_WFP_PENDING_EVENT, ListEntry);
                if (pending->Event.EventId == verdict->EventId && pending->Delivered)
                {
                    found = pending;
                    RemoveEntryList(entry);
                    InterlockedDecrement(&gPendingCount);
                    break;
                }
            }
            if (IsListEmpty(&gPendingList))
            {
                KeClearEvent(&gEventAvailable);
            }
            KeReleaseInStackQueuedSpinLock(&lockHandle);

            if (found == NULL)
            {
                status = STATUS_NOT_FOUND;
                break;
            }

            PfWfpCompletePendingEvent(found);
            status = STATUS_SUCCESS;
        }
        break;

    default:
        break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID
PfWfpUnload(_In_ PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    InterlockedExchange(&gUnloading, TRUE);
    PfWfpPermitAllPending();

    KeSetEvent(&gReaperStopEvent, IO_NO_INCREMENT, FALSE);
    if (gReaperThreadObject != NULL)
    {
        KeWaitForSingleObject(
            gReaperThreadObject,
            Executive,
            KernelMode,
            FALSE,
            NULL);
        ObDereferenceObject(gReaperThreadObject);
        gReaperThreadObject = NULL;
    }
    if (gReaperThreadHandle != NULL)
    {
        ZwClose(gReaperThreadHandle);
        gReaperThreadHandle = NULL;
    }

    if (gCalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(gCalloutIdV4);
        gCalloutIdV4 = 0;
    }
    if (gCalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(gCalloutIdV6);
        gCalloutIdV6 = 0;
    }

    if (gInjectionHandleV4 != NULL)
    {
        FwpsInjectionHandleDestroy0(gInjectionHandleV4);
        gInjectionHandleV4 = NULL;
    }
    if (gInjectionHandleV6 != NULL)
    {
        FwpsInjectionHandleDestroy0(gInjectionHandleV6);
        gInjectionHandleV6 = NULL;
    }

    if (gEngineHandle != NULL)
    {
        FwpmEngineClose0(gEngineHandle);
        gEngineHandle = NULL;
    }

    IoDeleteSymbolicLink(&gDosDeviceName);

    if (gDeviceObject != NULL)
    {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    DECLARE_CONST_UNICODE_STRING(deviceSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)");

    UNREFERENCED_PARAMETER(registryPath);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    InitializeListHead(&gPendingList);
    KeInitializeSpinLock(&gPendingLock);
    KeInitializeEvent(&gEventAvailable, NotificationEvent, FALSE);
    KeInitializeEvent(&gReaperStopEvent, NotificationEvent, FALSE);
    gUnloading = FALSE;
    gConnectedClients = 0;
    gPendingCount = 0;
    gNextEventId = 1;

    RtlInitUnicodeString(&deviceName, PF_WFP_DEVICE_NAME);
    status = IoCreateDeviceSecure(
        driverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceSddl,
        NULL,
        &gDeviceObject);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlInitUnicodeString(&gDosDeviceName, PF_WFP_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&gDosDeviceName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
        return status;
    }

    gDeviceObject->Flags |= DO_BUFFERED_IO;
    driverObject->DriverUnload = PfWfpUnload;
    driverObject->MajorFunction[IRP_MJ_CREATE] = PfWfpDispatchCreate;
    driverObject->MajorFunction[IRP_MJ_CLEANUP] = PfWfpDispatchCleanup;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = PfWfpDispatchClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PfWfpDispatchIoctl;

    status = PfWfpInitializeCallouts();
    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&gDosDeviceName);
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
        return status;
    }

    status = FwpsInjectionHandleCreate0(
        AF_INET,
        FWPS_INJECTION_TYPE_TRANSPORT,
        &gInjectionHandleV4);
    if (!NT_SUCCESS(status))
    {
        PfWfpUnload(driverObject);
        return status;
    }

    status = FwpsInjectionHandleCreate0(
        AF_INET6,
        FWPS_INJECTION_TYPE_TRANSPORT,
        &gInjectionHandleV6);
    if (!NT_SUCCESS(status))
    {
        PfWfpUnload(driverObject);
        return status;
    }

    status = PsCreateSystemThread(
        &gReaperThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        PfWfpReaperThread,
        NULL);
    if (!NT_SUCCESS(status))
    {
        PfWfpUnload(driverObject);
        return status;
    }

    status = ObReferenceObjectByHandle(
        gReaperThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        &gReaperThreadObject,
        NULL);
    if (!NT_SUCCESS(status))
    {
        LARGE_INTEGER waitTimeout;
        waitTimeout.QuadPart = -10000000LL;
        KeSetEvent(&gReaperStopEvent, IO_NO_INCREMENT, FALSE);
        ZwWaitForSingleObject(gReaperThreadHandle, FALSE, &waitTimeout);
        ZwClose(gReaperThreadHandle);
        gReaperThreadHandle = NULL;
        PfWfpUnload(driverObject);
        return status;
    }

    return STATUS_SUCCESS;
}
