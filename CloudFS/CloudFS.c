/*++
Module Name: CloudFS.c
Abstract: This is the main module of the CloudFS miniFilter driver.
Environment: Kernel mode.
This file was initially build by Visual Studio 2013, developed by Attila Zsigmond @ Budapest University of Technology and Economics
*/

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>


/*************************************************************************
Constant expression definitions.
*************************************************************************/

#define MIN_SECTOR_SIZE 0x200


/*************************************************************************
Struct definitions.
*************************************************************************/

//This is acontext structure that is used to pass sector size between IRQL levels across the filter.
typedef struct _VOLUME_CONTEXT
{
	ULONG SectorSize;
} VOLUME_CONTEXT, *PVOLUME_CONTEXT;

//This is a context structure that is used to pass state from our pre-operation callback to our post-operation callback.
typedef struct _PRE_TO_POST_CONTEXT
{
	//  Pointer to our volume context structure.  We always get the context
	//  in the preOperation path because you can not safely get it at DPC
	//  level.  We then release it in the postOperation path.  It is safe
	//  to release contexts at DPC level.
	PVOLUME_CONTEXT VolumeContext;

	//  Since the post-operation parameters always receive the "original"
	//  parameters passed to the operation, we need to pass our new destination
	//  buffer to our post operation routine so we can free it.
	PVOID SwappedBuffer;

} PRE_TO_POST_CONTEXT, *PPRE_TO_POST_CONTEXT;

typedef struct _MESSAGE_INFO
{
	ULONG Length;
	ULONG Reserved;
	UCHAR Content[65536];
	LARGE_INTEGER ByteOffset;

} MESSAGE_INFO, *PMESSAGE_INFO;

typedef struct _MESSAGE_REPLY_INFO
{
	ULONG Length;
	UCHAR Content[65536];
} MESSAGE_REPLY_INFO, *PMESSAGE_REPLY_INFO;

typedef struct _FILTER_MESSAGE_REPLY
{
	FILTER_REPLY_HEADER ReplyHeader;
	MESSAGE_REPLY_INFO Reply;

} FILTER_MESSAGE_REPLY, *PFILTER_MESSAGE_REPLY;

typedef struct _INTERCEPTION_CONTEXT
{
	BOOLEAN InterceptData;
} INTERCEPTION_CONTEXT, *PINTERCEPTION_CONTEXT;

/*************************************************************************
Global variables.
*************************************************************************/

PFLT_FILTER gFilterHandle;
PFLT_PORT gServerPort;
PFLT_PORT gClientPort;
PEPROCESS gUserProcess;
ULONG_PTR OperationStatusCtx = 1;
PUNICODE_STRING Folders;
ULONG FolderCount;
NPAGED_LOOKASIDE_LIST PreToPostContextList;

/*************************************************************************
    Prototypes of functions
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
CloudFSInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
CloudFSInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
CloudFSInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
CloudFSUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
CloudFSInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CloudFSPreCreate(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

VOID
CloudFSOperationStatusCallback(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
_In_ NTSTATUS OperationStatus,
_In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
CloudFSPostCreate(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
CloudFSPostRead(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
CloudFSPreWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
CloudFSPreOperationNoPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

BOOLEAN
CloudFSDoRequestOperationStatus(
_In_ PFLT_CALLBACK_DATA Data
);

NTSTATUS
FilterInstanceMessage(
_In_ PVOID ConnectionCookie,
_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
_In_ ULONG InputBufferSize,
_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
_In_ ULONG OutputBufferSize,
_Out_ PULONG ReturnOutputBufferLength);

NTSTATUS
FilterInstanceConnect(
_In_ PFLT_PORT ClientPort,
_In_ PVOID ServerPortCookie,
_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
_In_ ULONG SizeOfContext,
_Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
);

VOID
FilterInstanceDisconnect(
_In_opt_ PVOID ConnectionCookie
);

VOID
FreeUnicodeString(
_Inout_ PUNICODE_STRING String
);

NTSTATUS
AllocateUnicodeString(
_Inout_ PUNICODE_STRING String
);

NTSTATUS
ReadConfiguration(
_In_ PUNICODE_STRING RegistryPath
);

FLT_POSTOP_CALLBACK_STATUS
PostReadWhenSafe(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
CloudFSPreWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
CloudFSPreRead(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
CloudFSPostWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

/*************************************************************************
Initialization: text sections, global variables, etc.
*************************************************************************/

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, ReadConfiguration)
#pragma alloc_text(PAGE, CloudFSUnload)
#pragma alloc_text(PAGE, CloudFSInstanceQueryTeardown)
#pragma alloc_text(PAGE, CloudFSInstanceSetup)
#pragma alloc_text(PAGE, CloudFSInstanceTeardownStart)
#pragma alloc_text(PAGE, CloudFSInstanceTeardownComplete)
#pragma alloc_text(PAGE, CloudFSPreRead)
#pragma alloc_text(PAGE, CloudFSPostRead)
#pragma alloc_text(PAGE, PostReadWhenSafe)
#pragma alloc_text(PAGE, CloudFSPreWrite)
#pragma alloc_text(PAGE, CloudFSPostWrite)
#pragma alloc_text(PAGE, AllocateUnicodeString)
#pragma alloc_text(PAGE, FreeUnicodeString)
#pragma alloc_text(PAGE, FilterInstanceConnect)
#pragma alloc_text(PAGE, FilterInstanceDisconnect)
#pragma alloc_text(PAGE, FilterInstanceMessage)
#endif


//
//  context registration
//

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAMHANDLE_CONTEXT,
	0,
	NULL,
	sizeof(INTERCEPTION_CONTEXT),
	'cfCS' },

	{ FLT_VOLUME_CONTEXT,
	0,
	NULL,
	sizeof(VOLUME_CONTEXT),
	'cfCV' },

	{ FLT_CONTEXT_END }
};

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      CloudFSPreCreate,
      CloudFSPostCreate },

	{ IRP_MJ_READ,
	  0,
	  CloudFSPreRead,
	  CloudFSPostRead },

	{ IRP_MJ_WRITE,
	  0,
	  CloudFSPreWrite,
	  CloudFSPostWrite },

	/*

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_CLOSE,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_SET_EA,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      CloudFSPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_PNP,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      CloudFSPreOperation,
      CloudFSPostOperation },

	*/

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    ContextRegistration,                //  Context
    Callbacks,                          //  Operation callbacks

    CloudFSUnload,                           //  MiniFilterUnload

    CloudFSInstanceSetup,                    //  InstanceSetup
    CloudFSInstanceQueryTeardown,            //  InstanceQueryTeardown
    CloudFSInstanceTeardownStart,            //  InstanceTeardownStart
    CloudFSInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};


/*************************************************************************
Minifilter Instance initialization and unload routines.
*************************************************************************/

/*++
Routine Description:
This routine is called whenever a new instance is created on a volume. This gives us a chance to decide if we need to attach to this volume or not. If this routine is not defined in the registration structure, automatic instances are always created.

Arguments:
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance and its associated volume.
Flags - Flags describing the reason for this attach request.

Return Value:
STATUS_SUCCESS - attach
STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
NTSTATUS
CloudFSInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )

{
    PAGED_CODE();

	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status;
	NTSTATUS returnStatus = STATUS_FLT_DO_NOT_ATTACH;
	PVOLUME_CONTEXT volumeContext = NULL;
	UCHAR volPropsBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
	PFLT_VOLUME_PROPERTIES volProps = (PFLT_VOLUME_PROPERTIES)volPropsBuffer;
	ULONG retLen;

	//Prevent attaching to network volumes.
	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	//Attach only to NTFS volumes beacuse of Sparse Files feature
	if (VolumeFilesystemType != FLT_FSTYPE_NTFS)
	{
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	try
	{
		//Allocate a volume context structure - get volume name and sector size
		status = FltAllocateContext(
			FltObjects->Filter,
			FLT_VOLUME_CONTEXT,
			sizeof(VOLUME_CONTEXT),
			NonPagedPool,
			&volumeContext);

		if (!NT_SUCCESS(status))
		{
			//We could not allocate a context, quit now
			leave;
		}

		//Always get the volume properties, so I can get a sector size
		status = FltGetVolumeProperties(
			FltObjects->Volume,
			volProps,
			sizeof(volPropsBuffer),
			&retLen);

		if (!NT_SUCCESS(status))
		{
			leave;
		}

		//
		//  Save the sector size in the context for later use.  Note that
		//  we will pick a minimum sector size if a sector size is not
		//  specified.
		//

		FLT_ASSERT((volProps->SectorSize == 0) || (volProps->SectorSize >= MIN_SECTOR_SIZE));

		volumeContext->SectorSize = max(volProps->SectorSize, MIN_SECTOR_SIZE);

		status = FltSetVolumeContext(
			FltObjects->Volume,
			FLT_SET_CONTEXT_KEEP_IF_EXISTS,
			volumeContext,
			NULL);

		//Overwrite happens - we are good with it
		if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED || status == STATUS_SUCCESS)
		{
			returnStatus = STATUS_SUCCESS;
		}
	}
	finally
	{
		//Release the context. If the set failed, it will free the context.
		if (volumeContext != NULL)
		{
			FltReleaseContext(volumeContext);
		}
	}

	//Now we are ready to go
    return returnStatus;
}


/*++
Routine Description:
This is called when an instance is being manually deleted by a call to FltDetachVolume or FilterDetach thereby giving us a chance to fail that detach request. If this routine is not defined in the registration structure, explicit detach requests via FltDetachVolume or FilterDetach will always be failed.

Arguments:
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance and its associated volume.
Flags - Indicating where this detach request came from.

Return Value:
Returns the status of this operation.

--*/
NTSTATUS
CloudFSInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DbgPrint("CloudFS!CloudFSInstanceQueryTeardown: Entered\n");

    return STATUS_SUCCESS;
}

/*++

Routine Description:
This routine is called at the start of instance teardown.

Arguments:
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance and its associated volume.
Flags - Reason why this instance is being deleted.

Return Value:
None.

--*/
VOID
CloudFSInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    DbgPrint("CloudFS!CloudFSInstanceTeardownStart: Entered\n");
}

/*++
Routine Description:
This routine is called at the end of instance teardown.

Arguments:
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance and its associated volume.
Flags - Reason why this instance is being deleted.

Return Value:
None.
--*/
VOID
CloudFSInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    DbgPrint("CloudFS!CloudFSInstanceTeardownComplete: Entered\n");
}


/*************************************************************************
    MiniFilter (global) initialization and unload routines.
*************************************************************************/

/*++
Routine Description:
This is the initialization routine for this miniFilter driver. This registers with FltMgr and initializes all global data structures.

Arguments:
DriverObject - Pointer to driver object created by the system to represent this driver.
RegistryPath - Unicode string identifying where the parameters for this driver are located in the registry.

Return Value:
Routine can return non success error codes.
--*/
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
    NTSTATUS status = STATUS_SUCCESS;

    DbgPrint("CloudFS!DriverEntry: Entered\n");

	//Default to NonPagedPoolNx for non paged pool allocations where supported
	//to prevent data execution
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //Register with FltMgr to tell it our callback routines
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status))
	{
		//Read from registry to global variables
		FolderCount = 0;
		status = ReadConfiguration(RegistryPath);

		//If config was read successfully, continue, otherwise exit
		if (NT_SUCCESS(status))
		{
			//Build lookaside list
			ExInitializeNPagedLookasideList(
				&PreToPostContextList,
				NULL,
				NULL,
				0,
				sizeof(PRE_TO_POST_CONTEXT),
				'CFpp',
				0);

			//Build security descriptor
			status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

			//Security descriptor was built: continue, otherwise exit
			if (NT_SUCCESS(status))
			{
				//Configure messaging callbacks and create filter port
				RtlInitUnicodeString(&uniString, L"\\CloudFSMinifilterPort");

				InitializeObjectAttributes(&oa,
					&uniString,
					OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
					NULL,
					sd);

				status = FltCreateCommunicationPort(gFilterHandle,
					&gServerPort,
					&oa,
					NULL,
					FilterInstanceConnect,
					FilterInstanceDisconnect,
					FilterInstanceMessage,
					1);

				FltFreeSecurityDescriptor(sd);

				//Communication port created successfully - start filter, otherwise exit.
				if (NT_SUCCESS(status))
				{
					//Start filtering
					status = FltStartFiltering(gFilterHandle);
				}
			}
		}

		if (!NT_SUCCESS(status))
		{
			//Clean up Folders structure
			//In case of failure - release resources allocated above
			while (FolderCount > 0)
			{
				FolderCount--;
				FreeUnicodeString(Folders + FolderCount);
			}

			//Only one folder remaining - let's remove it
			if (Folders != NULL)
			{
				ExFreePoolWithTag(Folders, 'SCfg');
			}

			Folders = NULL;

			//Release lookaside list
			ExDeleteNPagedLookasideList(&PreToPostContextList);

			//Start failed: unregister
			FltUnregisterFilter(gFilterHandle);
		}
    }

    return status;
}

/*++
Routine Description:
This is the unload routine for this miniFilter driver. This is called when the minifilter is about to be unloaded. We can fail this unload request if this is not a mandatory unload indicated by the Flags parameter.

Arguments:
Flags - Indicating if this is a mandatory unload.

Return Value:
Returns STATUS_SUCCESS.
--*/
NTSTATUS
CloudFSUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    DbgPrint("CloudFS!CloudFSUnload: Entered\n");

	//Release resources allocated in ReadConfiguration
	while (FolderCount > 0)
	{
		FolderCount--;
		FreeUnicodeString(Folders + FolderCount);
	}

	//Only one folder remaining - let's remove it
	if (Folders != NULL)
	{
		ExFreePoolWithTag(Folders, 'SCfg');
	}
	Folders = NULL;

	FltCloseCommunicationPort(gServerPort);

	ExDeleteNPagedLookasideList(&PreToPostContextList);

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

/*************************************************************************
MiniFilter callback routines.
*************************************************************************/

/*++

Routine Description:
This is called whenever a user mode application wishes to communicate with this minifilter.

Arguments:
ConnectionCookie - unused
OperationCode - An identifier describing what type of message this is.  These codes are defined by the MiniFilter.
InputBuffer - A buffer containing input data, can be NULL if there is no input data.
InputBufferSize - The size in bytes of the InputBuffer.
OutputBuffer - A buffer provided by the application that originated the communication in which to store data to be returned to this application.
OutputBufferSize - The size in bytes of the OutputBuffer.
ReturnOutputBufferSize - The size in bytes of meaningful data returned in the OutputBuffer.

Return Value:
Returns the status of processing the message.

--*/
NTSTATUS
FilterInstanceMessage(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferLength)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

	//
	//                      **** PLEASE READ ****
	//
	//  The INPUT and OUTPUT buffers are raw user mode addresses.  The filter
	//  manager has already done a ProbedForRead (on InputBuffer) and
	//  ProbedForWrite (on OutputBuffer) which guarentees they are valid
	//  addresses based on the access (user mode vs. kernel mode).  The
	//  minifilter does not need to do their own probe.
	//
	//  The filter manager is NOT doing any alignment checking on the pointers.
	//  The minifilter must do this themselves if they care (see below).
	//
	//  The minifilter MUST continue to use a try/except around any access to
	//  these buffers.
	//
	try
	{
		if (InputBufferSize > 0 && InputBuffer != NULL)
		{
			for (UINT16 i = 0; i < InputBufferSize; i++)
			{
				UINT8 msg = ((PUINT8)InputBuffer)[i];
				DbgPrint("Filter instance message received. Pos: %i Value: %i", i, msg);
			}
		}
		else
		{
			DbgPrint("Filter instance message received without associated data.");
		}
	}
	except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Filter instance message receive exception occured.");
	}
	return STATUS_SUCCESS;
}


/*++

Routine Description:
This is called when user-mode connects to the server port - to establish a connection

Arguments:
ClientPort - This is the pointer to the client port that will be used to send messages from the filter.
ServerPortCookie - unused
ConnectionContext - unused
SizeofContext   - unused
ConnectionCookie - unused

Return Value:
STATUS_SUCCESS - to accept the connection
--
*/
NTSTATUS
FilterInstanceConnect(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	FLT_ASSERT(gClientPort == NULL);
	FLT_ASSERT(gUserProcess == NULL);

	//  Set the user process and port.
	gUserProcess = PsGetCurrentProcess();
	gClientPort = ClientPort;

	DbgPrint("User-mode application connected to CloudFS filter.\n");
	return STATUS_SUCCESS;
}

/*++

Routine Description
This is called when the connection is torn-down. We use it to close our handle to the connection

Arguments
ConnectionCookie - unused

Return value
None
--*/
VOID
FilterInstanceDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ConnectionCookie);

	//  Close our handle, reset stored process value
	FltCloseClientPort(gFilterHandle, &gClientPort);
	gUserProcess = NULL;

	DbgPrint("User-mode application disconnected from CloudFS filter.\n");
}






/*++
Routine Description:
This routine is a pre-operation dispatch routine for this miniFilter. This is non-pageable because it could be called on the paging path

Arguments:
Data - Pointer to the filter callbackData that is passed to us.
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
CompletionContext - The context for the completion routine for this operation.

Return Value:
The return value is the status of the operation.
--*/
FLT_PREOP_CALLBACK_STATUS
CloudFSPreCreate(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	//Eliminate processing file operations initiated by the user-mode process
	if (IoThreadToProcess(Data->Thread) == gUserProcess)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Return FLT_PREOP_SUCCESS_WITH_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


/*++
Routine Description:

This routine is called when the given operation returns from the call to IoCallDriver. This is useful for operations where STATUS_PENDING means the operation was successfully queued.  This is useful for OpLocks and directory change notification operations.
This callback is called in the context of the originating thread and will never be called at DPC level.  The file object has been correctly referenced so that you can access it.  It will be automatically dereferenced upon return.
This is non-pageable because it could be called on the paging path

Arguments:
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
RequesterContext - The context for the completion routine for this operation.
OperationStatus -

Return Value:
The return value is the status of the operation.
--*/
VOID
CloudFSOperationStatusCallback(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
_In_ NTSTATUS OperationStatus,
_In_ PVOID RequesterContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(ParameterSnapshot);
	UNREFERENCED_PARAMETER(OperationStatus);
	UNREFERENCED_PARAMETER(RequesterContext);

	//DbgPrint("CloudFS!CloudFSOperationStatusCallback: Entered\n");
}

/*++
Routine Description:

This routine is the post-operation completion routine for this miniFilter. This is non-pageable because it may be called at DPC level.

Arguments:
Data - Pointer to the filter callbackData that is passed to us.
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
CompletionContext - The completion context set in the pre-operation routine.
Flags - Denotes whether the completion is successful or is being drained.

Return Value:
The return value is the status of the operation.
--*/
FLT_POSTOP_CALLBACK_STATUS
CloudFSPostCreate(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	//Create operation fails - return now
	if (!NT_SUCCESS(Data->IoStatus.Status) || (STATUS_REPARSE == Data->IoStatus.Status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FltObjects != NULL)
	{
		if (FltObjects->FileObject != NULL)
		{
			POBJECT_NAME_INFORMATION objectNameInformation;

			NTSTATUS status = IoQueryFileDosDeviceName(FltObjects->FileObject, &objectNameInformation);
			if (NT_SUCCESS(status) && (objectNameInformation != NULL))
			{
				UNICODE_STRING fullFileName = objectNameInformation->Name;

				ULONG count;
				BOOLEAN match = FALSE;
				for (count = 0; (count < FolderCount && !match); count++)
				{
					USHORT originalLength = fullFileName.Length;
					fullFileName.Length = (Folders + count)->Length;
					if (RtlCompareUnicodeString(&fullFileName, Folders + count, TRUE) == 0)
					{
						match = TRUE;
					}
					fullFileName.Length = originalLength;
				}

				if (match)
				{
					ULONG tmp;
					NTSTATUS spStatus = 0;
					//FILE_STANDARD_INFORMATION standardInfo;
					//FILE_ZERO_DATA_INFORMATION fzdi;
					//LONGLONG fileSize = 0;
					FILE_BASIC_INFORMATION basicInfo;
					PINTERCEPTION_CONTEXT interceptionContext;
					NTSTATUS ctxStatus = 0;

					
					//Add stream handle context object to track this file handle
					ctxStatus = FltAllocateContext(
						FltObjects->Filter,
						FLT_STREAMHANDLE_CONTEXT,
						sizeof(INTERCEPTION_CONTEXT),
						PagedPool,
						&interceptionContext);

					if (NT_SUCCESS(ctxStatus))
					{
						//Set the handle context.
						interceptionContext->InterceptData = TRUE;

						FltSetStreamHandleContext(
							FltObjects->Instance,
							FltObjects->FileObject,
							FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
							interceptionContext,
							NULL);

						//Context is copied to the file object - release local copy
						FltReleaseContext(interceptionContext);
					}
					

					//ctxStatus error: handle not tracked, abort necessary here.

					//Query file information to determine sparseness
					spStatus = FltQueryInformationFile(
						FltObjects->Instance,
						FltObjects->FileObject,
						&basicInfo,
						sizeof(FILE_BASIC_INFORMATION),
						FileBasicInformation,
						NULL);
					
					if (NT_SUCCESS(spStatus))
					{
						//If we are unable to query parameters, it is not worth to mess with sparseness
						if ((basicInfo.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) == 0)
						{
							//If not sparse, make it sparse
							//We will use another file object to do this operation
							//otherwise we may get access denied here
							FILE_SET_SPARSE_BUFFER sparseBuffer;
							sparseBuffer.SetSparse = TRUE;

							HANDLE fileHandle;
							PFILE_OBJECT pFileObject;
							OBJECT_ATTRIBUTES fileObjectAttributes;
							IO_STATUS_BLOCK iosb;
							UNICODE_STRING openedFileName;
							openedFileName.MaximumLength = 1024;
							UNICODE_STRING volumeName;
							volumeName.MaximumLength = 260;

							AllocateUnicodeString(&volumeName);
							FltGetVolumeName(FltObjects->Volume, &volumeName, &tmp);

							AllocateUnicodeString(&openedFileName);
							RtlAppendUnicodeStringToString(&openedFileName, &volumeName);
							RtlAppendUnicodeStringToString(&openedFileName, &(FltObjects->FileObject->FileName));

							//Iitialize object attributes.
							InitializeObjectAttributes(
								&fileObjectAttributes,
								&openedFileName,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL);

							//Get file our own file object
							spStatus = FltCreateFileEx(
								FltObjects->Filter,
								FltObjects->Instance,
								&fileHandle,
								&pFileObject,
								FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
								&fileObjectAttributes,
								&iosb,
								NULL, // allocation is meaningless
								0, //no attributes specified
								FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, //complete share
								FILE_OPEN, // must already exist
								FILE_NON_DIRECTORY_FILE, // must NOT be a directory
								NULL, // no EA buffer
								0, // EA buffer length thus is 0
								0 // no flags passed
								);

							if (NT_SUCCESS(spStatus) && fileHandle != NULL && pFileObject != NULL)
							{
								spStatus = FltFsControlFile(
									FltObjects->Instance,
									pFileObject,
									FSCTL_SET_SPARSE,
									&sparseBuffer,
									sizeof(sparseBuffer),
									NULL,
									0,
									&tmp);

								//spStatus error: file is not sparse, we are losing space with a bunch of zeros

								FltClose(fileHandle);
							}

							FreeUnicodeString(&openedFileName);
							FreeUnicodeString(&volumeName);
						}

						/*
						//Querying for FileStandardInformation gives you the offset of EOF - the file length
						spStatus = FltQueryInformationFile(
							FltObjects->Instance,
							FltObjects->FileObject,
							&standardInfo,
							sizeof(FILE_STANDARD_INFORMATION),
							FileStandardInformation,
							NULL);

						if (NT_SUCCESS(spStatus))
						{
							//We succeeded in querying file length
							fileSize = standardInfo.EndOfFile.QuadPart;

							fzdi.FileOffset.QuadPart = 0;
							fzdi.BeyondFinalZero.QuadPart = 0 + fileSize;

							
							// Mark the range as sparse zero block
							// Causes zero blocks in read!
							spStatus = FltFsControlFile(
								FltObjects->Instance,
								FltObjects->FileObject,
								FSCTL_SET_ZERO_DATA,
								&fzdi,
								sizeof(FILE_ZERO_DATA_INFORMATION),
								NULL,
								0,
								&tmp);
							

							
						}
						*/

						DbgPrint("File under control: %wZ\n", &fullFileName);
					}



				} // end of: if(match)

			}
		}
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}


/*++

Routine Description:
This routine is a pre-operation dispatch routine for this miniFilter. This is non-pageable because it could be called on the paging path

Arguments:
Data - Pointer to the filter callbackData that is passed to us.
FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
CompletionContext - The context for the completion routine for this operation.
Return Value:

The return value is the status of the operation.

--*/
FLT_PREOP_CALLBACK_STATUS
CloudFSPreOperationNoPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	//DbgPrint("CloudFS!CloudFSPreOperationNoPostOperation: Entered\n");

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


/*++
Routine Description:
This identifies those operations we want the operation status for. These are typically operations that return STATUS_PENDING as a normal completion status.

Arguments:

Return Value:

TRUE - If we want the operation status
FALSE - If we don't

--*/
BOOLEAN
CloudFSDoRequestOperationStatus(
_In_ PFLT_CALLBACK_DATA Data
)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//  return boolean state based on which operations we are interested in
	return (BOOLEAN)
		//Check for oplock operations
		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&

		((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

		||

		//Check for directy change notification
		((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) && (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
		);
}






/*++
Routine Description:
This callback routine is executed before sending down a write IRP.
In this routine we check the stream handle context first - if it belongs to us, then we
have to send the data up to user-mode, and write all zeros to file. Request fails: stop operation

Arguments:

Return Value:
FLT_PREOP_SUCCESS_NO_CALLBACK - continue processing IRP
FLT_PREOP_COMPLETE - abort processing IRP
--*/
FLT_PREOP_CALLBACK_STATUS
CloudFSPreWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	PINTERCEPTION_CONTEXT interceptionContext;
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PVOID newBuf = NULL;
	PMDL newMdl = NULL;
	PVOLUME_CONTEXT volumeContext = NULL;
	PPRE_TO_POST_CONTEXT pretopostContext;
	PVOID origBuf;
	NTSTATUS status;
	ULONG writeLen = Data->Iopb->Parameters.Write.Length;

	try
	{

		//Trying to write ZERO bytes, then don't do anything
		if (writeLen == 0)
		{
			leave;
		}

		//Check tracking
		status = FltGetStreamHandleContext(FltObjects->Instance,
			FltObjects->FileObject,
			&interceptionContext);

		if (interceptionContext != NULL)
		{
			FltReleaseContext(interceptionContext);
		}

		if (!NT_SUCCESS(status))
		{
			//No context - let this IRP go - no postOp.
			leave;
		}

		//Get volume context for sector size
		status = FltGetVolumeContext(
			FltObjects->Filter,
			FltObjects->Volume,
			&volumeContext);

		if (!NT_SUCCESS(status))
		{
			leave;
		}

		//  If this is a non-cached I/O we need to round the length up to the
		//  sector size for this device.  We must do this because the file
		//  systems do this and we need to make sure our buffer is as big
		//  as they are expecting.
		if (FlagOn(IRP_NOCACHE, Data->Iopb->IrpFlags))
		{
			writeLen = (ULONG)ROUND_TO_SIZE(writeLen, volumeContext->SectorSize);
		}

		//Allocate aligned nonPaged memory for the buffer we are swapping to.
		newBuf = FltAllocatePoolAlignedWithTag(
			FltObjects->Instance,
			NonPagedPool,
			(SIZE_T)writeLen,
			'CFbs');

		if (newBuf == NULL)
		{
			leave;
		}

		//We only need to build a MDL for IRP operations. FASTIO interface has no parameter in which it receives MDL.
		if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
		{
			//Allocate a MDL for the new allocated memory
			newMdl = IoAllocateMdl(
				newBuf,
				writeLen,
				FALSE,
				FALSE,
				NULL);

			if (newMdl == NULL)
			{
				leave;
			}

			MmBuildMdlForNonPagedPool(newMdl);
		}

		//If the users original buffer had a MDL, get a system address.
		if (Data->Iopb->Parameters.Write.MdlAddress != NULL)
		{
			//This should be a simple MDL. We don't expect chained MDLs this high up the stack
			FLT_ASSERT(((PMDL)Data->Iopb->Parameters.Write.MdlAddress)->Next == NULL);

			origBuf = MmGetSystemAddressForMdlSafe(
				Data->Iopb->Parameters.Write.MdlAddress,
				NormalPagePriority);

			if (origBuf == NULL)
			{
				//If we could not get a system address for the users buffer,
				//then we are going to fail this operation.
				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				retValue = FLT_PREOP_COMPLETE;
				leave;
			}

		}
		else
		{
			//There was no MDL defined, use the given buffer address.
			origBuf = Data->Iopb->Parameters.Write.WriteBuffer;
		}

		//Copy the memory, we must do this inside the try/except because we may be using a users buffer address
		try
		{
			//We will send origBuf up

			RtlCopyMemory(newBuf, origBuf, writeLen);

			//Manipulation - this will be filled with zeros
			PUCHAR tempBuffer = newBuf;
			if (writeLen >= 6)
			{
				tempBuffer[0] = 65;
				tempBuffer[1] = 66;
				tempBuffer[2] = 67;
			}
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{
			//The copy failed, return an error, failing the operation.
			Data->IoStatus.Status = GetExceptionCode();
			Data->IoStatus.Information = 0;
			retValue = FLT_PREOP_COMPLETE;
			leave;
		}

		//We are ready to swap buffers, get a pre2Post context structure.
		//We need it to pass the volume context and the allocate memory buffer to the post operation callback.
		pretopostContext = ExAllocateFromNPagedLookasideList(&PreToPostContextList);

		if (pretopostContext == NULL)
		{
			leave;
		}

		//Swap buffers
		Data->Iopb->Parameters.Write.WriteBuffer = newBuf;
		Data->Iopb->Parameters.Write.MdlAddress = newMdl;
		FltSetCallbackDataDirty(Data);

		//Pass state to our post-operation callback.
		pretopostContext->SwappedBuffer = newBuf;
		pretopostContext->VolumeContext = volumeContext;
		*CompletionContext = pretopostContext;

		//Return we want a post-operation callback
		retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	}
	finally
	{
		//If we don't want a post-operation callback, then free the buffer or MDL if it was allocated.
		if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
		{

			if (newBuf != NULL)
			{
				FltFreePoolAlignedWithTag(
					FltObjects->Instance,
					newBuf,
					'CFbs');
			}

			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}

			if (volumeContext != NULL)
			{
				FltReleaseContext(volumeContext);
			}
		}
	}

	return retValue;
}




/*++
Routine Description:

Arguments:

Return Value:

FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeation callback
FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback

--*/
FLT_PREOP_CALLBACK_STATUS
CloudFSPreRead(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	FLT_PREOP_CALLBACK_STATUS retValue = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PVOID newBuf = NULL;
	PMDL newMdl = NULL;
	PVOLUME_CONTEXT volumeContext = NULL;
	PPRE_TO_POST_CONTEXT pretopostContext;
	PINTERCEPTION_CONTEXT interceptionContext;
	NTSTATUS status;	
	ULONG length = Data->Iopb->Parameters.Read.Length;

	try
	{
		//If they are trying to read ZERO bytes, then don't do anything
		//we don't need a post-operation callback.
		if (length == 0)
		{
			leave;
		}
		
		status = FltGetStreamHandleContext(FltObjects->Instance,
			FltObjects->FileObject,
			&interceptionContext);

		if (interceptionContext != NULL)
		{
			FltReleaseContext(interceptionContext);
		}

		if (!NT_SUCCESS(status))
		{
			//No context - let this IRP go - no postOp.
			leave;
		}
		
		//Get our volume context
		status = FltGetVolumeContext(
			FltObjects->Filter,
			FltObjects->Volume,
			&volumeContext);

		if (!NT_SUCCESS(status))
		{
			leave;
		}

		//  If this is a non-cached I/O we need to round the length up to the
		//  sector size for this device.  We must do this because the file
		//  systems do this and we need to make sure our buffer is as big
		//  as they are expecting.
		if (FlagOn(IRP_NOCACHE, Data->Iopb->IrpFlags))
		{
			length = (ULONG)ROUND_TO_SIZE(length, volumeContext->SectorSize);
		}

		//
		//  Allocate aligned nonPaged memory for the buffer we are swapping
		//  to. This is really only necessary for noncached IO but we always
		//  do it here for simplification. If we fail to get the memory, just
		//  don't swap buffers on this operation.
		newBuf = FltAllocatePoolAlignedWithTag(
			FltObjects->Instance,
			NonPagedPool,
			(SIZE_T)length,
			'CFbs');

		if (newBuf == NULL)
		{
			leave;
		}

		//
		//  We only need to build a MDL for IRP operations.  We don't need to
		//  do this for a FASTIO operation since the FASTIO interface has no
		//  parameter for passing the MDL to the file system.
		if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
		{
			//Allocate a MDL for the new allocated memory.
			newMdl = IoAllocateMdl(
				newBuf,
				length,
				FALSE,
				FALSE,
				NULL);

			if (newMdl == NULL)
			{
				leave;
			}

			MmBuildMdlForNonPagedPool(newMdl);
		}

		//
		//  We are ready to swap buffers, get a pre2Post context structure.
		//  We need it to pass the volume context and the allocate memory
		//  buffer to the post operation callback.

		pretopostContext = ExAllocateFromNPagedLookasideList(&PreToPostContextList);

		if (pretopostContext == NULL)
		{
			leave;
		}

		//Our own buffer is going downwards
		Data->Iopb->Parameters.Read.ReadBuffer = newBuf;
		Data->Iopb->Parameters.Read.MdlAddress = newMdl;
		FltSetCallbackDataDirty(Data);

		pretopostContext->SwappedBuffer = newBuf;
		pretopostContext->VolumeContext = volumeContext;

		*CompletionContext = pretopostContext;

		//  Return we want a post-operation callback
		retValue = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	}
	finally
	{
		//  If we don't want a post-operation callback, then cleanup state.
		if (retValue != FLT_PREOP_SUCCESS_WITH_CALLBACK)
		{
			if (newBuf != NULL)
			{
				FltFreePoolAlignedWithTag(
					FltObjects->Instance,
					newBuf,
					'CFbs');
			}

			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}

			if (volumeContext != NULL)
			{
				FltReleaseContext(volumeContext);
			}
		}
	}

	return retValue;
}







/*++
Routine Description:
This callback routine is executed before sending up a read IRP.
In this routine we check the stream handle context first - if it belongs to us, then we
have to request data from user-mode. Request fails: stop operation.

Arguments:

Return Value:
always FLT_POSTOP_FINISHED_PROCESSING - continue processing IRP

--*/
FLT_POSTOP_CALLBACK_STATUS
CloudFSPostRead(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	ULONG length;
	NTSTATUS status;
	PINTERCEPTION_CONTEXT interceptionContext;
	PVOID extBuffer;
	PPRE_TO_POST_CONTEXT pretopostContext = CompletionContext;
	FLT_POSTOP_CALLBACK_STATUS retValue = FLT_POSTOP_FINISHED_PROCESSING;
	BOOLEAN cleanupAllocatedBuffer = TRUE;

	FLT_ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

	try
	{
		//If the operation failed, there is no data to copy so just return now.
		if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == 0))
		{
			leave;
		}
		
		status = FltGetStreamHandleContext(FltObjects->Instance,
			FltObjects->FileObject,
			&interceptionContext);

		if (interceptionContext != NULL)
		{
			FltReleaseContext(interceptionContext);
		}

		if (!NT_SUCCESS(status))
		{
			//No context - let this IRP go
			leave;
		}
		
		//In the following section only tracked IRPs are being processed
		length = Data->Iopb->Parameters.Read.Length;

		//Gain access to the data buffer
		if (Data->Iopb->Parameters.Read.MdlAddress == NULL)
		{
			if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) || FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
			{
				//If this is a system buffer, just use the given address because it is valid in all thread contexts.
				//If this is a FASTIO operation, we can just use the buffer (inside a try/except) since we know we are in the correct thread context (you can't pend FASTIO's).
				extBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
			}
			else
			{
				//We don't have a MDL and this is not a system buffer or a fastio so this is probably some arbitrary user buffer.
				//Let's get to a safe IRQL so we can do the processing.
				BOOLEAN processSafe = FltDoCompletionProcessingWhenSafe(
					Data,
					FltObjects,
					CompletionContext,
					Flags,
					PostReadWhenSafe,
					&retValue);

				if (processSafe)
				{
					//  This operation has been moved to a safe IRQL, the called
					//  routine will do (or has done) the freeing so don't do it
					//  in our routine.
					cleanupAllocatedBuffer = FALSE;
				}
				else
				{
					//  We are in a state where we can not get to a safe IRQL and
					//  we do not have a MDL.  There is nothing we can do to safely
					//  copy the data back to the users buffer, fail the operation
					//  and return.  This shouldn't ever happen because in those
					//  situations where it is not safe to post, we should have
					//  a MDL.
					Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
					Data->IoStatus.Information = 0;
				}
				leave;
			}
		}
		else
		{
			FLT_ASSERT(((PMDL)Data->Iopb->Parameters.Read.MdlAddress)->Next == NULL);
			
			extBuffer = MmGetSystemAddressForMdlSafe(
				Data->Iopb->Parameters.Read.MdlAddress,
				NormalPagePriority);
			
			if (extBuffer == NULL)
			{
				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				leave;
			}
		}

		//We have access - keep going
		try
		{
			//Manipulation
			PUCHAR tempBuffer = pretopostContext->SwappedBuffer;
			if (Data->IoStatus.Information >= 6)
			{
				tempBuffer[3] = 75;
				tempBuffer[4] = 76;
				tempBuffer[5] = 77;
			}

			//Data->IoStatus.Information - bytes successfully transferred
			RtlCopyMemory(extBuffer, pretopostContext->SwappedBuffer, Data->IoStatus.Information);
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{
			Data->IoStatus.Status = GetExceptionCode();
			Data->IoStatus.Information = 0;
		}
	}
	finally
	{
		//
		//  If we are supposed to, cleanup the allocated memory and release
		//  the volume context.  The freeing of the MDL (if there is one) is
		//  handled by FltMgr.
		//

		if (cleanupAllocatedBuffer)
		{
			FltFreePoolAlignedWithTag(
				FltObjects->Instance,
				pretopostContext->SwappedBuffer,
				'CFbs');

			FltReleaseContext(pretopostContext->VolumeContext);

			ExFreeToNPagedLookasideList(&PreToPostContextList, pretopostContext);
		}
	}

	return retValue;
}


/*++

Routine Description:
In post-write operation, we release all our allocated resources. The Filter Manager swaps the buffers back.

Arguments:


Return Value:

--*/
FLT_POSTOP_CALLBACK_STATUS
CloudFSPostWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(Data);

	PINTERCEPTION_CONTEXT interceptionContext;

	NTSTATUS status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&interceptionContext);

	if (interceptionContext != NULL)
	{
		FltReleaseContext(interceptionContext);
	}

	if (NT_SUCCESS(status))
	{
		//This is a tracked operation
		PPRE_TO_POST_CONTEXT pretopostContext = CompletionContext;

		//Free allocated POOL and volume context
		FltFreePoolAlignedWithTag(
			FltObjects->Instance,
			pretopostContext->SwappedBuffer,
			'CFbs');

		FltReleaseContext(pretopostContext->VolumeContext);

		ExFreeToNPagedLookasideList(&PreToPostContextList, pretopostContext);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}



/*************************************************************************
Helper functions
*************************************************************************/


/*++
Routine Description:
This is a callback routine for safe Post-Read processing.

Arguments:

Return Value:
FLT_POSTOP_FINISHED_PROCESSING - continue processing IRP
no way to cancel
--*/
FLT_POSTOP_CALLBACK_STATUS
PostReadWhenSafe(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status;
	PVOID extBuffer;
	//PUCHAR buffer;
	//ULONG length = Data->Iopb->Parameters.Read.Length;
	//ULONG i = 0;
	PPRE_TO_POST_CONTEXT pretopostContext = CompletionContext;

	//This is some sort of user buffer without a MDL, lock the user buffer so we can access it.
	//This routine will create a MDL for it.
	status = FltLockUserBuffer(Data);

	if (!NT_SUCCESS(status))
	{
		Data->IoStatus.Status = status;
		Data->IoStatus.Information = 0;
	}
	else
	{
		//Get a system address for this buffer.

		extBuffer = MmGetSystemAddressForMdlSafe(
			Data->Iopb->Parameters.Read.MdlAddress,
			NormalPagePriority);

		if (extBuffer == NULL)
		{
			//  If we couldn't get a system buffer address, fail the operation
			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Information = 0;
		}
		else
		{
			RtlCopyMemory(extBuffer, pretopostContext->SwappedBuffer, Data->IoStatus.Information);

			/*
			length = Data->Iopb->Parameters.Read.Length;
			buffer = ExAllocatePoolWithTag(NonPagedPool, length, 'Rbuf');
			if (buffer != NULL)
			{
				//We will fill this buffer from user mode - now its full of A-s
				for (i = 0; i < length; i++)
				{
					buffer[i] = 65;
				}

				//System buffer address - try/except unnecessary.
				RtlCopyMemory(extBuffer, buffer, length);

				ExFreePoolWithTag(buffer, 'Rbuf');
			}
			*/
		}
	}

	FltFreePoolAlignedWithTag(
		FltObjects->Instance,
		pretopostContext->SwappedBuffer,
		'CFbs');

	FltReleaseContext(pretopostContext->VolumeContext);

	ExFreeToNPagedLookasideList(&PreToPostContextList, pretopostContext);

	return FLT_POSTOP_FINISHED_PROCESSING;
}






/*++
Routine Descrition:
This routine reads filter configuration from the registry: specify folders to watch.

Arguments:
RegistryPath - The path key passed to the driver during DriverEntry.

Return Value:
STATUS_SUCCESS if the function completes successfully.
Otherwise a valid NTSTATUS code is returned.
--*/
NTSTATUS
ReadConfiguration(
_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES attributes;
	HANDLE driverRegKey = NULL;
	UNICODE_STRING valueName;
	PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
	ULONG valueLength = 0;
	BOOLEAN closeHandle = FALSE;
	PWCHAR ch;
	SIZE_T length;
	ULONG count;
	PUNICODE_STRING folder;

	PAGED_CODE();

	//Init global variables.
	Folders = NULL;
	FolderCount = 0;

	//Open the driver registry key
	InitializeObjectAttributes(&attributes,
		RegistryPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	//I would rather use FltXxx routines, but there are no registry-handling FltXxx routines.
	//ZwXxx kernel routines don't check their parameters - we have to be really careful.

	//Open key - close and release at the end of this routine
	status = ZwOpenKey(&driverRegKey,
		KEY_READ,
		&attributes);

	if (!NT_SUCCESS(status))
	{
		goto LabelReadConfigurationCleanup;
	}

	//Handle is open - we have to close it
	closeHandle = TRUE;

	//Query the length of the registry value - key: FoldersUnderControl
	RtlInitUnicodeString(&valueName, L"FoldersUnderControl");

	status = ZwQueryValueKey(driverRegKey,
		&valueName,
		KeyValuePartialInformation,
		NULL, //we only need the length to allocate buffer first
		0,
		&valueLength);

	if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
	{
		status = STATUS_INVALID_PARAMETER;
		goto LabelReadConfigurationCleanup;
	}

	//Allocate buffer upon the extracted length
	valueBuffer = ExAllocatePoolWithTag(NonPagedPool,
		valueLength,
		'RCfg');

	if (valueBuffer == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto LabelReadConfigurationCleanup;
	}

	//Get the value of the registry key
	status = ZwQueryValueKey(driverRegKey,
		&valueName,
		KeyValuePartialInformation,
		valueBuffer, //value goes here
		valueLength,
		&valueLength);

	if (!NT_SUCCESS(status))
	{
		goto LabelReadConfigurationCleanup;
	}

	
	//Count how many strings are in the multi string
	//Point to first char, and count them - classic zero-terminated strings
	ch = (PWCHAR)(valueBuffer->Data);
	count = 0;
	while (*ch != '\0')
	{
		ch = ch + wcslen(ch) + 1;
		count++;
	}

	//Allocate memory for those strings
	Folders = ExAllocatePoolWithTag(PagedPool,
		count * sizeof(UNICODE_STRING),
		'SCfg');

	if (Folders == NULL)
	{
		goto LabelReadConfigurationCleanup;
	}

	//Convert them to UNICODE_STRING, and copy to the allocated memory
	ch = (PWCHAR)((PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer->Data);
	folder = Folders;

	while (FolderCount < count)
	{
		length = wcslen(ch) * sizeof(WCHAR);
		folder->MaximumLength = (USHORT)length;

		status = AllocateUnicodeString(folder);

		if (!NT_SUCCESS(status))
		{
			goto LabelReadConfigurationCleanup;
		}

		folder->Length = (USHORT)length;

		RtlCopyMemory(folder->Buffer, ch, length);

		//Move to next string in input
		ch = ch + length / sizeof(WCHAR) + 1;

		//Increase count
		FolderCount++;

		//Move to next structure
		folder++;
	}

LabelReadConfigurationCleanup:

	//
	//  Note that this function leaks the global buffers.
	//  On failure DriverEntry will clean up the globals
	//  so we don't have to do that here.
	//

	if (valueBuffer != NULL)
	{
		ExFreePoolWithTag(valueBuffer, 'RCfg');
		valueBuffer = NULL;
	}

	if (closeHandle)
	{
		//If we have the handle opened - close it
		ZwClose(driverRegKey);
	}

	if (!NT_SUCCESS(status))
	{
		//In case of failure - release resources allocated above
		while (FolderCount > 0)
		{
			FolderCount--;
			FreeUnicodeString(Folders + FolderCount);
		}

		//Only one folder remaining - let's remove it
		if (Folders != NULL)
		{
			ExFreePoolWithTag(Folders, 'SCfg');
		}

		Folders = NULL;
	}

	return status;
}


/*++
Routine Description:
This routine allocates a unicode string

Arguments:
String - supplies the size of the string to be allocated in the MaximumLength field
return the unicode string

Return Value:
STATUS_SUCCESS                  - success
STATUS_INSUFFICIENT_RESOURCES   - failure
--*/
NTSTATUS
AllocateUnicodeString(
	_Inout_ PUNICODE_STRING String
)

{
	PAGED_CODE();
	String->Buffer = ExAllocatePoolWithTag(NonPagedPool, String->MaximumLength, 'MStr');
	if (String->Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	String->Length = 0;
	return STATUS_SUCCESS;
}

/*++
Routine Description:
This routine frees a unicode string

Arguments:
String - supplies the string to be freed

Return Value:
None

--*/
VOID
FreeUnicodeString(
	_Inout_ PUNICODE_STRING String
)
{
	PAGED_CODE();
	if (String->Buffer)
	{
		ExFreePoolWithTag(String->Buffer, 'MStr');
		String->Buffer = NULL;
	}
	String->Length = 0;
	String->MaximumLength = 0;
	String->Buffer = NULL;
}

