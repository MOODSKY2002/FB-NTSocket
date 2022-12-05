type in_addr_t as ulong

type in_addr
	s_addr as in_addr_t
end type

type SOCKADDR_IN
	sin_family as short
	sin_port   as ushort
	sin_addr   as IN_ADDR
	sin_zero   as zstring * 8
end type

type _UNICODE_STRING
	Length as USHORT
	MaximumLength as USHORT
	Buffer as PWSTR
end type
type UNICODE_STRING as _UNICODE_STRING
type PUNICODE_STRING as _UNICODE_STRING ptr

type _OBJECT_ATTRIBUTES
	Length as ULONG
	RootDirectory as HANDLE
	ObjectName as PUNICODE_STRING
	Attributes as ULONG
	SecurityDescriptor as PVOID
	SecurityQualityOfService as PVOID
end type

type OBJECT_ATTRIBUTES as _OBJECT_ATTRIBUTES
type POBJECT_ATTRIBUTES as _OBJECT_ATTRIBUTES ptr
type PCOBJECT_ATTRIBUTES as const OBJECT_ATTRIBUTES ptr

type _IO_STATUS_BLOCK
   UNION
      Status as NTSTATUS
      Pointer as PVOID   
   END UNION
   Information as ULONG_PTR
end type
type IO_STATUS_BLOCK  as _IO_STATUS_BLOCK
type PIO_STATUS_BLOCK as _IO_STATUS_BLOCK Ptr

type PIO_APC_ROUTINE as sub(byval as PVOID, byval as PIO_STATUS_BLOCK, byval as ULONG)

Declare Function NtDeviceIoControlFile Lib "NTDLL.DLL" alias "NtDeviceIoControlFile" (byval DeviceHandle as HANDLE, byval Event as HANDLE, byval UserApcRoutine as PIO_APC_ROUTINE, byval UserApcContext as PVOID, byval IoStatusBlock as PIO_STATUS_BLOCK, byval IoControlCode as ULONG, byval InputBuffer as PVOID, byval InputBufferSize as ULONG, byval OutputBuffer as PVOID, byval OutputBufferSize as ULONG) as NTSTATUS
declare function RtlIpv4AddressToStringW Lib "NTDLL.DLL" alias "RtlIpv4AddressToStringW" (Addr as IN_ADDR ptr, S as LPWSTR) as NTSTATUS

type guint16 as ushort
#define GUINT16_SWAP_LE_BE_CONSTANT(val) cast(guint16, cast(guint16, cast(guint16, (val)) shr 8) or cast(guint16, cast(guint16, (val)) shl 8))
#define GUINT16_SWAP_LE_BE(val) GUINT16_SWAP_LE_BE_CONSTANT(val)
#define GUINT16_TO_BE(val) GUINT16_SWAP_LE_BE(val)
#define g_htons(val) GUINT16_TO_BE(val)

#define STATUS_SUCCESS CAST(NTSTATUS,&H00000000L)
#define IOCTL_AFD_GET_PEER_NAME &H0001203F
#define IOCTL_AFD_GET_SOCK_NAME &H0001202F

'解析SOCKADDR,取回IPv4与端口
private function Get_SOCKADDR_Info_V4(byval sInfo as SOCKADDR_IN,byref sIP as wstring ptr,byref sPort as long) as long
   RtlIpv4AddressToStringW @sInfo.sin_addr,sIP
   sPort = g_htons(sInfo.sin_port)
   function = sPort
end function

'获取通讯中使用的本地IP及端口
function DDK_GetSockName_V4(byval s as SOCKET,ByRef sIP As wString ptr,ByRef sPort As Long) As Long
   dim sStatus as NTSTATUS 
   dim IOSB    as IO_STATUS_BLOCK
   Dim sInfo   As SOCKADDR_IN
   
   sStatus = NtDeviceIoControlFile(s,null,NULL,NULL,@IOSB,IOCTL_AFD_GET_SOCK_NAME,null,0,@sInfo,sizeof(SOCKADDR_IN))
   if sStatus = STATUS_SUCCESS then 
      if Get_SOCKADDR_Info_V4(sInfo,sIP,sPort) > 0 then return 1
   ELSE
      RETURN sStatus
   end if
end function

'获取通讯中使用的远程IP及端口
function DDK_GetPeerName_V4(byval s as SOCKET,ByRef sIP As wString ptr,ByRef sPort As Long) As Long
   dim sStatus as NTSTATUS 
   dim IOSB    as IO_STATUS_BLOCK
   Dim sInfo   As SOCKADDR_IN
   
   sStatus = NtDeviceIoControlFile(s,null,NULL,NULL,@IOSB,IOCTL_AFD_GET_PEER_NAME,null,0,@sInfo,sizeof(SOCKADDR_IN))
   if sStatus = STATUS_SUCCESS then 
      if Get_SOCKADDR_Info_V4(sInfo,sIP,sPort) > 0 then return 1
   ELSE
      RETURN sStatus
   end if
end function