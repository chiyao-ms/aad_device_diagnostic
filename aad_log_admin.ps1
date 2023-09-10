# All global parameters

# Setting the output width buffer of Out-File to 10000
$PSDefaultParameterValues['out-file:width'] = 10000

# Get the log folder
$global:root_folder = "C:\AAD_Logs\"
$temp_log_root_folder = Get-ChildItem $global:root_folder -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$global:full_folder = $global:root_folder+$temp_log_root_folder 

# Start Transcript
Start-Transcript -Path $(Join-Path -Path $global:full_folder -ChildPath "transcript-admin.log") -Append -IncludeInvocationHeader

# Get the current working folder
$global:current_Folder = (Get-Location).Path

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Check !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$global:verbose_output = $false
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Check !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

$global:full_script_logs_folder = ""
$global:full_eventlog_folder = ""
$global:full_reg_folder = ""
$global:full_cert_folder = ""
$global:full_net_folder = ""
$global:full_wam_folder = ""
$global:full_etw_folder = ""

$global:event_list = @(
    "Microsoft-Windows-AAD/Operational",
    "Microsoft-Windows-AAD/Analytic", #Not
    "Microsoft-Windows-Biometrics/Operational", 
    "Microsoft-Windows-CAPI2/Operational",
    "Microsoft-Windows-HelloForBusiness/Operational",
    "Microsoft-Windows-Kerberos/Operational",
    "Microsoft-Windows-User Device Registration/Admin",
    "Microsoft-Windows-User Device Registration/Debug",
    "Microsoft-Windows-Workplace Join/Admin",
    "Microsoft-Windows-WebAuth/Operational",
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    #"Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Autopilot",
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational",
    "Microsoft-Windows-TaskScheduler/Operational"
)

$global:event_log_disabled_by_default = @()
$global:CAPI2_Default_Size = 1052672

# All EWT GUID
####################################################
#                ETW Providers
####################################################
#=================================================== WAM_Providers ===================================================
$WAM_Providers =
@'
{077b8c4a-e425-578d-f1ac-6fdf1220ff68} 0xFFFFFFFF 0xff
{5836994d-a677-53e7-1389-588ad1420cc5} 0xFFFFFFFF 0xff
{86510A0A-FDF4-44FC-B42F-50DD7D77D10D} 0xFFFFFFFF 0xff
{6ae51639-98eb-4c04-9b88-9b313abe700f} 0xFFFFFFFF 0xff
{F7C77B8D-3E3D-4AA5-A7C5-1DB8B20BD7F0} 0xFFFFFFFF 0xff
{556045FD-58C5-4A97-9881-B121F68B79C5} 0xFFFFFFFF 0xff
{EC3CA551-21E9-47D0-9742-1195429831BB} 0xFFFFFFFF 0xff
{5AF52B0D-E633-4ead-828A-4B85B8DAAC2B} 0xFFFF 0xff
{2A6FAF47-5449-4805-89A3-A504F3E221A6} 0xFFFF 0xff
{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b} 0xFFFFFFFF 0xff
{bb8dd8e5-3650-5ca7-4fea-46f75f152414} 0xFFFFFFFF 0xff
{7fad10b2-2f44-5bb2-1fd5-65d92f9c7290} 0xFFFFFFFF 0xff
{74D91EC4-4680-40D2-A213-45E2D2B95F50} 0xFFFFFFFF 0xff
{5A9ED43F-5126-4596-9034-1DCFEF15CD11} 0xFFFFFFFF 0xff
{05f02597-fe85-4e67-8542-69567ab8fd4f} 0xFFFFFFFF 0xff
{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F} 0xFFFFFFFF 0xff
{63b6c2d2-0440-44de-a674-aa51a251b123} 0xFFFFFFFF 0xff
{bfed9100-35d7-45d4-bfea-6c1d341d4c6b} 0xFFFFFFFF 0xff
{3C49678C-14AE-47FD-9D3A-4FEF5D796DB9} 0xFFFFFFFF 0xff
{7acf487e-104b-533e-f68a-a7e9b0431edb} 0xFFFFFFFF 0xff
{9EBB3B15-B094-41B1-A3B8-0F141B06BADD} 0xFFF 0xff
{7B79E9B1-DB01-465C-AC8E-97BA9714BDA2} 0xFFFFFFFF 0xff
{2A3C6602-411E-4DC6-B138-EA19D64F5BBA} 0xFFFF 0xff
{EF98103D-8D3A-4BEF-9DF2-2156563E64FA} 0xFFFF 0xff
{FB6A424F-B5D6-4329-B9B5-A975B3A93EAD} 0x000003FF
{D93FE84A-795E-4608-80EC-CE29A96C8658} 0x7FFFFFFF 0xff
{3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5} 0x7 0xff
{B1108F75-3252-4b66-9239-80FD47E06494} 0x2FF 0xff
{C10B942D-AE1B-4786-BC66-052E5B4BE40E} 0x3FF 0xff
{82c7d3df-434d-44fc-a7cc-453a8075144e} 0x2FF 0xff
{4180c4f7-e238-5519-338f-ec214f0b49aa} 0xFFFFFFFF 0xff
{EB65A492-86C0-406A-BACE-9912D595BD69} 0xFFFFFFFF 0xff 
{d49918cf-9489-4bf1-9d7b-014d864cf71f} 0xFFFFFFFF 0xff
{ac01ece8-0b79-5cdb-9615-1b6a4c5fc871} 0xFFFFFFFF 0xff 
{1941f2b9-0939-5d15-d529-cd333c8fed83} 0xffffffffffffffff 0xff
{0001376b-930d-50cd-2b29-491ca938cd54} 0xffffffffffffffff 0xff
{072665fb-8953-5a85-931d-d06aeab3d109} 0xffffffffffffffff 0xff
{f6a774e5-2fc7-5151-6220-e514f1f387b6} 0xffffffffffffffff 0xff
{a48e7274-bb8f-520d-7e6f-1737e9d68491} 0xffffffffffffffff 0xff
{88cd9180-4491-4640-b571-e3bee2527943} 0xffffffffffffffff 0xff
{833e7812-d1e2-5172-66fd-4dd4b255a3bb} 0xffffffffffffffff 0xff
{30ad9f59-ec19-54b2-4bdf-76dbfc7404a6} 0xffffffffffffffff 0xff
{d229987f-edc3-5274-26bf-82be01d6d97e} 0xffffffffffffffff 0xff
{8cde46fc-ca33-50ff-42b3-c64c1c731037} 0xffffffffffffffff 0xff
{25756703-e23b-4647-a3cb-cb24d473c193} 0xffffffffffffffff 0xff
{569cf830-214c-5629-79a8-4e9b58ea24bc} 0xffffffffffffffff 0xff 
{08B15CE7-C9FF-5E64-0D16-66589573C50F} 0xFFFFFF7F 0xff
{2745a526-23f5-4ef1-b1eb-db8932d43330} 0xffffffffffffffff 0xff
{c632d944-dddb-599f-a131-baf37bf22ef0} 0xffffffffffffffff 0xff
{EF00584A-2655-462C-BC24-E7DE630E7FBF} 0xffffffffffffffff 0xff
{d48533a7-98e4-566d-4956-12474e32a680} 0xffffffffffffffff 0xff
{0b618b2b-0310-431e-be64-09f4b3e3e6da} 0xffffffffffffffff 0xff
{20f61733-57f1-4127-9f48-4ab7a9308ae2} 0xffffffffffffffff 0xff
{b3a7698a-0c45-44da-b73d-e181c9b5c8e6} 0xffffffffffffffff 0xff
{4e749B6A-667D-4C72-80EF-373EE3246B08} 0xffffffffffffffff 0xff
'@
<#=================================================== WAM_Providers ===================================================
{077b8c4a-e425-578d-f1ac-6fdf1220ff68} 0xFFFFFFFF 0xff #Microsoft.Windows.Security.TokenBroker 
{5836994d-a677-53e7-1389-588ad1420cc5} 0xFFFFFFFF 0xff  #Microsoft.Windows.MicrosoftAccount.TBProvider 
{86510A0A-FDF4-44FC-B42F-50DD7D77D10D} 0xFFFFFFFF 0xff #AadBrokerPluginApp 
{6ae51639-98eb-4c04-9b88-9b313abe700f} 0xFFFFFFFF 0xff #AadWamPlugin 
{F7C77B8D-3E3D-4AA5-A7C5-1DB8B20BD7F0} 0xFFFFFFFF 0xff  #AadWamExtension 
    
# Cloud AP and Experience
{556045FD-58C5-4A97-9881-B121F68B79C5} 0xFFFFFFFF 0xff #AadCloudAPPlugin 
{EC3CA551-21E9-47D0-9742-1195429831BB} 0xFFFFFFFF 0xff  #cloudap 
{5AF52B0D-E633-4ead-828A-4B85B8DAAC2B} 0xFFFF 0xff #negoexts 
{2A6FAF47-5449-4805-89A3-A504F3E221A6} 0xFFFF 0xff  #pku2u 
{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b} 0xFFFFFFFF 0xff  
{bb8dd8e5-3650-5ca7-4fea-46f75f152414} 0xFFFFFFFF 0xff #Microsoft.Windows.Security.CloudAp 
{7fad10b2-2f44-5bb2-1fd5-65d92f9c7290} 0xFFFFFFFF 0xff #Microsoft.Windows.Security.CloudAp.Critical 
{74D91EC4-4680-40D2-A213-45E2D2B95F50} 0xFFFFFFFF 0xff #Microsoft.AAD.CloudAp.Provider 
{5A9ED43F-5126-4596-9034-1DCFEF15CD11} 0xFFFFFFFF 0xff  #AadCloudAPPluginBVTs 
    
# AAD and TokenBroker
{05f02597-fe85-4e67-8542-69567ab8fd4f} 0xFFFFFFFF 0xff #Microsoft-Windows-LiveId, MSAClientTraceLoggingProvider 
{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F} 0xFFFFFFFF 0xff #Microsoft-Windows-AAD 
{63b6c2d2-0440-44de-a674-aa51a251b123} 0xFFFFFFFF 0xff #Microsoft.Windows.BrokerInfrastructure 
{bfed9100-35d7-45d4-bfea-6c1d341d4c6b} 0xFFFFFFFF 0xff #AADPlugin 
{3C49678C-14AE-47FD-9D3A-4FEF5D796DB9} 0xFFFFFFFF 0xff
{7acf487e-104b-533e-f68a-a7e9b0431edb} 0xFFFFFFFF 0xff #Microsoft.Windows.Security.TokenBroker.BrowserSSO 
{9EBB3B15-B094-41B1-A3B8-0F141B06BADD} 0xFFF 0xff #AadAuthHelper 
{7B79E9B1-DB01-465C-AC8E-97BA9714BDA2} 0xFFFFFFFF 0xff #AadTB 
    
# WebAuth
{2A3C6602-411E-4DC6-B138-EA19D64F5BBA} 0xFFFF 0xff #webplatform 
{EF98103D-8D3A-4BEF-9DF2-2156563E64FA} 0xFFFF 0xff  #webauth 
{FB6A424F-B5D6-4329-B9B5-A975B3A93EAD} 0x000003FF #wdigest 
{D93FE84A-795E-4608-80EC-CE29A96C8658} 0x7FFFFFFF 0xff #idlisten 
{3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5} 0x7 0xff #wlidsvc 
{B1108F75-3252-4b66-9239-80FD47E06494} 0x2FF 0xff #IDCommon 
{C10B942D-AE1B-4786-BC66-052E5B4BE40E} 0x3FF 0xff  #livessp 
{82c7d3df-434d-44fc-a7cc-453a8075144e} 0x2FF 0xff #IdStoreLib 
{4180c4f7-e238-5519-338f-ec214f0b49aa} 0xFFFFFFFF 0xff  #Microsoft.Windows.ResourceManager 
{EB65A492-86C0-406A-BACE-9912D595BD69} 0xFFFFFFFF 0xff #Microsoft-Windows-AppModel-Exec 
{d49918cf-9489-4bf1-9d7b-014d864cf71f} 0xFFFFFFFF 0xff #Microsoft-Windows-ProcessStateManager    
{ac01ece8-0b79-5cdb-9615-1b6a4c5fc871} 0xFFFFFFFF 0xff #Microsoft.Windows.Application.Service
{1941f2b9-0939-5d15-d529-cd333c8fed83} 0xffffffffffffffff 0xff #Microsoft.Windows.BackgroundManager
{0001376b-930d-50cd-2b29-491ca938cd54} 0xffffffffffffffff 0xff #Microsoft.Windows.ProcessStateManager
{072665fb-8953-5a85-931d-d06aeab3d109} 0xffffffffffffffff 0xff #Microsoft.Windows.ProcessLifetimeManager 
{f6a774e5-2fc7-5151-6220-e514f1f387b6} 0xffffffffffffffff 0xff #Microsoft.Windows.HostActivityManager
{a48e7274-bb8f-520d-7e6f-1737e9d68491} 0xffffffffffffffff 0xff #Microsoft.Windows.System.RemoteSystem
{88cd9180-4491-4640-b571-e3bee2527943} 0xffffffffffffffff 0xff #Microsoft.Windows.PushNotifications.Platform
{833e7812-d1e2-5172-66fd-4dd4b255a3bb} 0xffffffffffffffff 0xff #Microsoft.Windows..C97111CB69Model.UserActivities
{30ad9f59-ec19-54b2-4bdf-76dbfc7404a6} 0xffffffffffffffff 0xff #Microsoft.Windows.CDP.Session
{d229987f-edc3-5274-26bf-82be01d6d97e} 0xffffffffffffffff 0xff #Microsoft.Windows.System.RemoteSystemSession
{8cde46fc-ca33-50ff-42b3-c64c1c731037} 0xffffffffffffffff 0xff #Microsoft.Windows.Application.SharePlatform
{25756703-e23b-4647-a3cb-cb24d473c193} 0xffffffffffffffff 0xff #Microsoft.Windows.Application.NearSharePlatform
{569cf830-214c-5629-79a8-4e9b58ea24bc} 0xffffffffffffffff 0xff  #Microsoft.Windows.Shell.ShareUX
{08B15CE7-C9FF-5E64-0D16-66589573C50F} 0xFFFFFF7F 0xff #Microsoft.Windows.Security.Fido
{2745a526-23f5-4ef1-b1eb-db8932d43330}!0xffffffffffffffff'     #Microsoft.Windows.Security.TrustedSignal <<< Only here
{c632d944-dddb-599f-a131-baf37bf22ef0}!0xffffffffffffffff'     #Microsoft.Windows.Security.NaturalAuth.Service <<< Only here
{EF00584A-2655-462C-BC24-E7DE630E7FBF}!0xffffffffffffffff'     #Microsoft.Windows.AppLifeCycle <<< Only here
{d48533a7-98e4-566d-4956-12474e32a680}!0xffffffffffffffff'     #RuntimeBrokerActivations  <<< Only here
{0b618b2b-0310-431e-be64-09f4b3e3e6da}!0xffffffffffffffff'     #Microsoft.Windows.Security.NaturalAuth.wpp <<< Only here
{20f61733-57f1-4127-9f48-4ab7a9308ae2}!0xffffffffffffffff' #InternetServer_wpp
{b3a7698a-0c45-44da-b73d-e181c9b5c8e6}!0xffffffffffffffff' #WinHttpWPP
{4e749B6A-667D-4C72-80EF-373EE3246B08}!0xffffffffffffffff' #WinINetWPP
'@
=================================================== WAM_Providers ===================================================#>


#=================================================== NGC_Providers ===================================================
$NGC_Providers=
@'
{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C} 0x0 0xff 0xff
{CAC8D861-7B16-5B6B-5FC0-85014776BDAC} 0x0 0xff
{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD} 0x0 0xff
{0ABA6892-455B-551D-7DA8-3A8F85225E1A} 0x0 0xff
{9DF6A82D-5174-5EBF-842A-39947C48BF2A} 0x0 0xff
{9B223F67-67A1-5B53-9126-4593FE81DF25} 0x0 0xff
{89F392FF-EE7C-56A3-3F61-2D5B31A36935} 0x0 0xff
{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF} 0x0 0xff
{1D6540CE-A81B-4E74-AD35-EEF8463F97F5} 0xffff 0xff
{CDC6BEB9-6D78-5138-D232-D951916AB98F} 0x0 0xff
{C0B2937D-E634-56A2-1451-7D678AA3BC53} 0x0 0xff
{9D4CA978-8A14-545E-C047-A45991F0E92F} 0x0 0xff
{3b9dbf69-e9f0-5389-d054-a94bc30e33f7} 0x0 0xff
{34646397-1635-5d14-4d2c-2febdcccf5e9} 0x0 0xff
{c12f629d-37d4-58f7-22a8-94ac45ad8648} 0x0 0xff
{3A8D6942-B034-48e2-B314-F69C2B4655A3} 0xffffffff 0xff
{5AA9A3A3-97D1-472B-966B-EFE700467603} 0xffffffff 0xff
{EAC19293-76ED-48C3-97D3-70D75DA61438} 0xffffffff 0xff
{23B8D46B-67DD-40A3-B636-D43E50552C6D} 0x0 0xff
{2056054C-97A6-5AE4-B181-38BC6B58007E} 0x0 0xff
{7955d36a-450b-5e2a-a079-95876bca450a} 0x0 0xff
{c3feb5bf-1a8d-53f3-aaa8-44496392bf69} 0x0 0xff
{78983c7d-917f-58da-e8d4-f393decf4ec0} 0x0 0xff
{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410} 0x0 0xff
{86D5FE65-0564-4618-B90B-E146049DEBF4} 0x0 0xff
{D5A5B540-C580-4DEE-8BB4-185E34AA00C5} 0x0 0xff
{9FBF7B95-0697-4935-ADA2-887BE9DF12BC} 0x0 0xff
{3DA494E4-0FE2-415C-B895-FB5265C5C83B} 0x0 0xff
{73370BD6-85E5-430B-B60A-FEA1285808A7} 0x0 0xff
{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43} 0x0 0xff
{54164045-7C50-4905-963F-E5BC1EEF0CCA} 0x0 0xff
{89A2278B-C662-4AFF-A06C-46AD3F220BCA} 0x0 0xff
{BC0669E1-A10D-4A78-834E-1CA3C806C93B} 0x0 0xff
{BEA18B89-126F-4155-9EE4-D36038B02680} 0x0 0xff
{B2D1F576-2E85-4489-B504-1861C40544B3} 0x0 0xff
{98BF1CD3-583E-4926-95EE-A61BF3F46470} 0x0 0xff
{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799} 0x0 0xff
{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b} 0xFFFFFFFF 0xff
{99eb7b56-f3c6-558c-b9f6-09a33abb4c83} 0xFFFFFFFF 0xff
{aa02d1a4-72d8-5f50-d425-7402ea09253a} 0x0 0xff
{507C53AE-AF42-5938-AEDE-4A9D908640ED} 0x0 0xff
{02ad713f-20d4-414f-89d0-da5a6f3470a9} 0xffffffffffffffff 0xff
{acc49822-f0b2-49ff-bff2-1092384822b6} 0xffffffffffffffff 0xff
{f245121c-b6d1-5f8a-ea55-498504b7379e} 0xffffffffffffffff 0xff
{6ad52b32-d609-4be9-ae07-ce8dae937e39} 0xffffffffffffffff 0xff
{f4aed7c7-a898-4627-b053-44a7caa12fcd} 0xffffffffffffffff 0xff
{ac01ece8-0b79-5cdb-9615-1b6a4c5fc871} 0xffffffffffffffff 0xff
'@
<#
    '{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C}!0x0'                # Microsoft.Windows.Security.NGC.KspSvc
    '{CAC8D861-7B16-5B6B-5FC0-85014776BDAC}!0x0'                # Microsoft.Windows.Security.NGC.CredProv
    '{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD}!0x0'                # Microsoft.Windows.Security.NGC.CryptNgc
    '{0ABA6892-455B-551D-7DA8-3A8F85225E1A}!0x0'                # Microsoft.Windows.Security.NGC.NgcCtnr
    '{9DF6A82D-5174-5EBF-842A-39947C48BF2A}!0x0'                # Microsoft.Windows.Security.NGC.NgcCtnrSvc
    '{9B223F67-67A1-5B53-9126-4593FE81DF25}!0x0'                # Microsoft.Windows.Security.NGC.KeyStaging
    '{89F392FF-EE7C-56A3-3F61-2D5B31A36935}!0x0'                # Microsoft.Windows.Security.NGC.CSP
    '{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF}!0x0'                # Microsoft.Windows.Security.NGC.LocalAccountMigPlugin
    '{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}!0xffff'             # Microsoft-Windows-Security-NGC-PopKeySrv
    '{CDC6BEB9-6D78-5138-D232-D951916AB98F}!0x0'                # Microsoft.Windows.Security.NGC.NgcIsoCtnr
    '{C0B2937D-E634-56A2-1451-7D678AA3BC53}!0x0'                # Microsoft.Windows.Security.Ngc.Truslet
    '{9D4CA978-8A14-545E-C047-A45991F0E92F}!0x0'                # Microsoft.Windows.Security.NGC.Recovery
    '{3b9dbf69-e9f0-5389-d054-a94bc30e33f7}!0x0'                # Microsoft.Windows.Security.NGC.Local
    '{34646397-1635-5d14-4d2c-2febdcccf5e9}!0x0'                # Microsoft.Windows.Security.NGC.KeyCredMgr
    '{c12f629d-37d4-58f7-22a8-94ac45ad8648}!0x0'                # Microsoft.Windows.Security.NGC.Utils
    '{3A8D6942-B034-48e2-B314-F69C2B4655A3}!0xffffffff'         # TPM
    '{5AA9A3A3-97D1-472B-966B-EFE700467603}!0xffffffff'         # TPM Virtual Smartcard card simulator
    '{EAC19293-76ED-48C3-97D3-70D75DA61438}!0xffffffff'         # Cryptographic TPM Endorsement Key Services
    '{23B8D46B-67DD-40A3-B636-D43E50552C6D}!0x0'                # Microsoft-Windows-User Device Registration (event)
    '{2056054C-97A6-5AE4-B181-38BC6B58007E}!0x0'                # Microsoft.Windows.Security.DeviceLock
    '{7955d36a-450b-5e2a-a079-95876bca450a}!0x0'                # Microsoft.Windows.Security.DevCredProv
    '{c3feb5bf-1a8d-53f3-aaa8-44496392bf69}!0x0'                # Microsoft.Windows.Security.DevCredSvc
    '{78983c7d-917f-58da-e8d4-f393decf4ec0}!0x0'                # Microsoft.Windows.Security.DevCredClient
    '{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410}!0x0'                # Microsoft.Windows.Security.DevCredWinRt
    '{86D5FE65-0564-4618-B90B-E146049DEBF4}!0x0'                # Microsoft.Windows.Security.DevCredTask
    '{D5A5B540-C580-4DEE-8BB4-185E34AA00C5}!0x0'                # MDM SCEP Trace
    '{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}!0x0'                # Microsoft-Windows-DM-Enrollment-Provider (event)
    '{3DA494E4-0FE2-415C-B895-FB5265C5C83B}!0x0'                # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider (event)
    '{73370BD6-85E5-430B-B60A-FEA1285808A7}!0x0'                # Microsoft-Windows-CertificateServicesClient (event)
    '{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43}!0x0'                # Microsoft-Windows-CertificateServicesClient-AutoEnrollment (event)
    '{54164045-7C50-4905-963F-E5BC1EEF0CCA}!0x0'                # Microsoft-Windows-CertificateServicesClient-CertEnroll (event)
    '{89A2278B-C662-4AFF-A06C-46AD3F220BCA}!0x0'                # Microsoft-Windows-CertificateServicesClient-CredentialRoaming (event)
    '{BC0669E1-A10D-4A78-834E-1CA3C806C93B}!0x0'                # Microsoft-Windows-CertificateServicesClient-Lifecycle-System (event)
    '{BEA18B89-126F-4155-9EE4-D36038B02680}!0x0'                # Microsoft-Windows-CertificateServicesClient-Lifecycle-User (event)
    '{B2D1F576-2E85-4489-B504-1861C40544B3}!0x0'                # Microsoft-Windows-CertificateServices-Deployment (event)
    '{98BF1CD3-583E-4926-95EE-A61BF3F46470}!0x0'                # Microsoft-Windows-CertificationAuthorityClient-CertCli (event)
    '{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799}!0x0'                # Microsoft-Windows-CertPolEng (event)
    '{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}!0xFFFFFFFF'         # Microsoft.Windows.Shell.CloudExperienceHost
    '{99eb7b56-f3c6-558c-b9f6-09a33abb4c83}!0xFFFFFFFF'         # Microsoft.Windows.Shell.CloudExperienceHost.Common
    '{aa02d1a4-72d8-5f50-d425-7402ea09253a}!0x0'                # Microsoft.Windows.Shell.CloudDomainJoin.Client
    '{507C53AE-AF42-5938-AEDE-4A9D908640ED}!0x0'                # Microsoft.Windows.Security.Credentials.UserConsentVerifier
    '{02ad713f-20d4-414f-89d0-da5a6f3470a9}!0xffffffffffffffff' # Microsoft.Windows.Security.CFL.API
    '{acc49822-f0b2-49ff-bff2-1092384822b6}!0xffffffffffffffff' # Microsoft.CAndE.ADFabric.CDJ
    '{f245121c-b6d1-5f8a-ea55-498504b7379e}!0xffffffffffffffff' # Microsoft.Windows.DeviceLockSettings
     {6ad52b32-d609-4be9-ae07-ce8dae937e39} 0xffffffffffffffff     # Microsoft-Windows-RPC
     {f4aed7c7-a898-4627-b053-44a7caa12fcd} 0xffffffffffffffff     # Microsoft-Windows-RPC-Events
     {ac01ece8-0b79-5cdb-9615-1b6a4c5fc871} 0xffffffffffffffff     # Microsoft.Windows.Application.Service    
#>
#=================================================== NGC_Providers ===================================================

#=================================================== Biometric_Providers ===================================================
$BIOM_Providers=
@'
{34BEC984-F11F-4F1F-BB9B-3BA33C8D0132} 0xffff 0xff
{225b3fed-0356-59d1-1f82-eed163299fa8} 0x0 0xff
{9dadd79b-d556-53f2-67c4-129fa62b7512} 0x0 0xff
{1B5106B1-7622-4740-AD81-D9C6EE74F124} 0x0 0xff
{1d480c11-3870-4b19-9144-47a53cd973bd} 0x0 0xff
{e60019f0-b378-42b6-a185-515914d3228c} 0x0 0xff
{48CAFA6C-73AA-499C-BDD8-C0D36F84813E} 0x0 0xff
{add0de40-32b0-4b58-9d5e-938b2f5c1d1f} 0x0 0xff
{e92355c0-41e4-4aed-8d67-df6b2058f090} 0x0 0xff
{85be49ea-38f1-4547-a604-80060202fb27} 0x0 0xff
{F4183A75-20D4-479B-967D-367DBF62A058} 0x0 0xff
{0279b50e-52bd-4ed6-a7fd-b683d9cdf45d} 0x0 0xff
{39A5AA08-031D-4777-A32D-ED386BF03470} 0x0 0xff
{22eb0808-0b6c-5cd4-5511-6a77e6e73a93} 0x0 0xff
{63221D5A-4D00-4BE3-9D38-DE9AAF5D0258} 0x0 0xff
{9df19cfa-e122-5343-284b-f3945ccd65b2} 0x0 0xff
{beb1a719-40d1-54e5-c207-232d48ac6dea} 0x0 0xff
{8A89BB02-E559-57DC-A64B-C12234B7572F} 0x0 0xff
{a0e3d8ea-c34f-4419-a1db-90435b8b21d0} 0xffffffffffffffff 0xff
'@
<#
    '{34BEC984-F11F-4F1F-BB9B-3BA33C8D0132}!0xffff'
    '{225b3fed-0356-59d1-1f82-eed163299fa8}!0x0'
    '{9dadd79b-d556-53f2-67c4-129fa62b7512}!0x0'
    '{1B5106B1-7622-4740-AD81-D9C6EE74F124}!0x0'
    '{1d480c11-3870-4b19-9144-47a53cd973bd}!0x0'
    '{e60019f0-b378-42b6-a185-515914d3228c}!0x0'
    '{48CAFA6C-73AA-499C-BDD8-C0D36F84813E}!0x0'
    '{add0de40-32b0-4b58-9d5e-938b2f5c1d1f}!0x0'
    '{e92355c0-41e4-4aed-8d67-df6b2058f090}!0x0'
    '{85be49ea-38f1-4547-a604-80060202fb27}!0x0'
    '{F4183A75-20D4-479B-967D-367DBF62A058}!0x0'
    '{0279b50e-52bd-4ed6-a7fd-b683d9cdf45d}!0x0'
    '{39A5AA08-031D-4777-A32D-ED386BF03470}!0x0'
    '{22eb0808-0b6c-5cd4-5511-6a77e6e73a93}!0x0'
    '{63221D5A-4D00-4BE3-9D38-DE9AAF5D0258}!0x0'
    '{9df19cfa-e122-5343-284b-f3945ccd65b2}!0x0'
    '{beb1a719-40d1-54e5-c207-232d48ac6dea}!0x0'
    '{8A89BB02-E559-57DC-A64B-C12234B7572F}!0x0'
    '{a0e3d8ea-c34f-4419-a1db-90435b8b21d0}!0xffffffffffffffff'
#>
#=================================================== Biometric_Providers ===================================================

#=================================================== LSA_Providers ===================================================
$LSA_Providers=
@'
{D0B639E0-E650-4D1D-8F39-1580ADE72784} 0xC43EFF 0xff
{169EC169-5B77-4A3E-9DB6-441799D5CACB} 0xffffff 0xff
{DAA76F6A-2D11-4399-A646-1D62B7380F15} 0xffffff 0xff
{366B218A-A5AA-4096-8131-0BDAFCC90E93} 0xfffffff 0xff
{4D9DFB91-4337-465A-A8B5-05A27D930D48} 0xff 0xff
{7FDD167C-79E5-4403-8C84-B7C0BB9923A1} 0xFFF 0xff
{CA030134-54CD-4130-9177-DAE76A3C5791} 0xfffffff 0xff
{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e} 0xffffffffffffffff 0xff
{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3} 0xffffffffffffffff 0xff
{C00D6865-9D89-47F1-8ACB-7777D43AC2B9} 0xffffffffffffffff 0xff
{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6} 0xffffffffffffffff 0xff
{794FE30E-A052-4B53-8E29-C49EF3FC8CBE} 0xffffffffffffffff 0xff
{ba634d53-0db8-55c4-d406-5c57a9dd0264} 0xffffffffffffffff 0xff
{45E7DBC5-E130-5CEF-9353-CC5EBF05E6C8} 0xFFFF 0xff
{A4E69072-8572-4669-96B7-8DB1520FC93A} 0xffffffffffffffff 0xff
{C5D12E1B-84A0-4fe6-9E5F-FEBA123EAE66} 0xffffffffffffffff 0xff
{E2E66F29-4D71-4646-8E58-20E204C3C25B} 0xffffffffffffffff 0xff
{6f2c1ee5-1dfd-519b-2d55-702756f5964d} 0xffffffffffffffff 0xff
{FB093D76-8964-11DF-9EA1-CB38E0D72085} 0xFFFF 0xff
{3353A14D-EE30-436E-8FF5-575A4351EA80} 0xFFFF 0xff
{afda4fd8-2fe5-5c75-ba0e-7d5c0b225e12} 0xffffffffffffffff 0xff
{cbb61b6d-a2cf-471a-9a58-a4cd5c08ffba} 0xff 0xff
'@
<#
    '{D0B639E0-E650-4D1D-8F39-1580ADE72784}!0xC43EFF'               # (WPP)LsaTraceControlGuid
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB}!0xffffff'               # LsaDs
    '{DAA76F6A-2D11-4399-A646-1D62B7380F15}!0xffffff'               # (WPP)LsaAuditTraceControlGuid
    '{366B218A-A5AA-4096-8131-0BDAFCC90E93}!0xfffffff'              # (WPP)LsaIsoTraceControlGuid
    '{4D9DFB91-4337-465A-A8B5-05A27D930D48}!0xff'                   # (TL)Microsoft.Windows.Security.LsaSrv
    '{7FDD167C-79E5-4403-8C84-B7C0BB9923A1}!0xFFF'                  # (WPP)VaultGlobalDebugTraceControlGuid
    '{CA030134-54CD-4130-9177-DAE76A3C5791}!0xfffffff'              # (WPP)NETLOGON
    '{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e}!0xffffffffffffffff'     # (WPP)VaultCDSTraceGuid
    '{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3}!0xffffffffffffffff'     # (WPP)GmsaClientTraceControlGuid
    '{C00D6865-9D89-47F1-8ACB-7777D43AC2B9}!0xffffffffffffffff'     # (WPP)CCGLaunchPadTraceControlGuid
    '{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6}!0xffffffffffffffff'     # (WPP)CCGTraceControlGuid
    '{794FE30E-A052-4B53-8E29-C49EF3FC8CBE}!0xffffffffffffffff'
    '{ba634d53-0db8-55c4-d406-5c57a9dd0264}!0xffffffffffffffff'     # (TL)Microsoft.Windows.Security.PasswordlessPolicy
    '{45E7DBC5-E130-5CEF-9353-CC5EBF05E6C8}!0xFFFF'                 # (EVT)Microsoft-Windows-Containers-CCG/Admin
    '{A4E69072-8572-4669-96B7-8DB1520FC93A}!0xffffffffffffffff'
    '{C5D12E1B-84A0-4fe6-9E5F-FEBA123EAE66}!0xffffffffffffffff'     # (WPP)RoamingSecurityDebugTraceControlGuid
    '{E2E66F29-4D71-4646-8E58-20E204C3C25B}!0xffffffffffffffff'     # (WPP)RoamingSecurityDebugTraceControlGuid
    '{6f2c1ee5-1dfd-519b-2d55-702756f5964d}!0xffffffffffffffff'
    '{FB093D76-8964-11DF-9EA1-CB38E0D72085}!0xFFFF'                 # (WPP)KDSSVCCtlGuid
    '{3353A14D-EE30-436E-8FF5-575A4351EA80}!0xFFFF'                 # (WPP)KDSPROVCtlGuid
    '{afda4fd8-2fe5-5c75-ba0e-7d5c0b225e12}!0xffffffffffffffff'
    '{cbb61b6d-a2cf-471a-9a58-a4cd5c08ffba}!0xff'                   # (WPP)UACLog
#>
#=================================================== LSA_Providers ===================================================

#=================================================== NTLM_Providers ===================================================
$NTLM_Prodivers=
@'
{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90} 0x5ffDf 0xff
{AC69AE5B-5B21-405F-8266-4424944A43E9} 0xffffffff 0xff
{6165F3E2-AE38-45D4-9B23-6B4818758BD9} 0xffffffff 0xff
{AC43300D-5FCC-4800-8E99-1BD3F85F0320} 0xffffffffffffffff 0xff
{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E} 0xffffffffffffffff 0xff
'@
<#
    '{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90}!0x5ffDf'
    '{AC69AE5B-5B21-405F-8266-4424944A43E9}!0xffffffff'
    '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}!0xffffffff'
    '{AC43300D-5FCC-4800-8E99-1BD3F85F0320}!0xffffffffffffffff'
    '{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E}!0xffffffffffffffff'
#>
#=================================================== NTLM_Providers ===================================================

#=================================================== KRB_Providers ===================================================
$KRB_Providers=
@'
{6B510852-3583-4e2d-AFFE-A67F9F223438} 0x7ffffff 0xff
{60A7AB7A-BC57-43E9-B78A-A1D516577AE3} 0xffffff 0xff
{FACB33C4-4513-4C38-AD1E-57C1F6828FC0} 0xffffffff 0xff
{97A38277-13C0-4394-A0B2-2A70B465D64F} 0xff 0xff
{8a4fc74e-b158-4fc1-a266-f7670c6aa75d} 0xffffffffffffffff 0xff
{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1} 0xffffffffffffffff 0xff
'@
<#
    '{6B510852-3583-4e2d-AFFE-A67F9F223438}!0x7ffffff'
    '{60A7AB7A-BC57-43E9-B78A-A1D516577AE3}!0xffffff'
    '{FACB33C4-4513-4C38-AD1E-57C1F6828FC0}!0xffffffff'
    '{97A38277-13C0-4394-A0B2-2A70B465D64F}!0xff'
    '{8a4fc74e-b158-4fc1-a266-f7670c6aa75d}!0xffffffffffffffff'
    '{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}!0xffffffffffffffff'
#>
#=================================================== KRB_Providers ===================================================

#=================================================== KDC_Providers ===================================================
$KDC_Providers=
@'
{1BBA8B19-7F31-43c0-9643-6E911F79A06B} 0xfffff 0xff
{f2c3d846-1d17-5388-62fa-3839e9c67c80} 0xffffffffffffffff 0xff
{6C51FAD2-BA7C-49b8-BF53-E60085C13D92} 0xffffffffffffffff 0xff
'@
<#
    '{1BBA8B19-7F31-43c0-9643-6E911F79A06B}!0xfffff'
    '{f2c3d846-1d17-5388-62fa-3839e9c67c80}!0xffffffffffffffff'
    '{6C51FAD2-BA7C-49b8-BF53-E60085C13D92}!0xffffffffffffffff'
#>
#=================================================== KDC_Providers ===================================================

#=================================================== SAM_Providers ===================================================
$SAM_Providers=
@'
{8E598056-8993-11D2-819E-0000F875A064} 0xffffffffffffffff 0xff
{0D4FDC09-8C27-494A-BDA0-505E4FD8ADAE} 0xffffffffffffffff 0xff
{BD8FEA17-5549-4B49-AA03-1981D16396A9} 0xffffffffffffffff 0xff
{F2969C49-B484-4485-B3B0-B908DA73CEBB} 0xffffffffffffffff 0xff
{548854B9-DA55-403E-B2C7-C3FE8EA02C3C} 0xffffffffffffffff 0xff
'@
<#
    '{8E598056-8993-11D2-819E-0000F875A064}!0xffffffffffffffff'
    '{0D4FDC09-8C27-494A-BDA0-505E4FD8ADAE}!0xffffffffffffffff'
    '{BD8FEA17-5549-4B49-AA03-1981D16396A9}!0xffffffffffffffff'
    '{F2969C49-B484-4485-B3B0-B908DA73CEBB}!0xffffffffffffffff'
    '{548854B9-DA55-403E-B2C7-C3FE8EA02C3C}!0xffffffffffffffff'
)
#>
#=================================================== SAM_Providers ===================================================

#=================================================== SSL_Providers ===================================================
$SSL_Providers=
@'
{37D2C3CD-C5D4-4587-8531-4696C44244C8} 0x4000ffff 0xff
'@
<#
    '{37D2C3CD-C5D4-4587-8531-4696C44244C8}!0x4000ffff'
#>
#=================================================== SSL_Providers ===================================================

#=================================================== Crypt_Providers ===================================================
$CRYPT_Providers=
@'
{EA3F84FC-03BB-540e-B6AA-9664F81A31FB} 0xFFFFFFFF 0xff
{A74EFE00-14BE-4ef9-9DA9-1484D5473302} 0xFFFFFFFF 0xff
{A74EFE00-14BE-4ef9-9DA9-1484D5473301} 0xFFFFFFFF 0xff
{A74EFE00-14BE-4ef9-9DA9-1484D5473303} 0xFFFFFFFF 0xff
{A74EFE00-14BE-4ef9-9DA9-1484D5473305} 0xFFFFFFFF 0xff
{786396CD-2FF3-53D3-D1CA-43E41D9FB73B} 0x0 0xff
{a74efe00-14be-4ef9-9da9-1484d5473304} 0xffffffffffffffff 0xff
{9d2a53b2-1411-5c1c-d88c-f2bf057645bb} 0xffffffffffffffff 0xff
'@
<#
    '{EA3F84FC-03BB-540e-B6AA-9664F81A31FB}!0xFFFFFFFF'
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473302}!0xFFFFFFFF'
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473301}!0xFFFFFFFF'
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473303}!0xFFFFFFFF'
    '{A74EFE00-14BE-4ef9-9DA9-1484D5473305}!0xFFFFFFFF'
    '{786396CD-2FF3-53D3-D1CA-43E41D9FB73B}!0x0'
    '{a74efe00-14be-4ef9-9da9-1484d5473304}!0xffffffffffffffff'
    '{9d2a53b2-1411-5c1c-d88c-f2bf057645bb}!0xffffffffffffffff'
#>
#=================================================== Crypt_Providers ===================================================

#=================================================== SMART_CARD_Providers ===================================================
$SMART_Providers=
@'
{30EAE751-411F-414C-988B-A8BFA8913F49} 0xffffffffffffffff 0xff
{13038E47-FFEC-425D-BC69-5707708075FE} 0xffffffffffffffff 0xff
{3FCE7C5F-FB3B-4BCE-A9D8-55CC0CE1CF01} 0xffffffffffffffff 0xff
{FB36CAF4-582B-4604-8841-9263574C4F2C} 0xffffffffffffffff 0xff
{133A980D-035D-4E2D-B250-94577AD8FCED} 0xffffffffffffffff 0xff
{EED7F3C9-62BA-400E-A001-658869DF9A91} 0xffffffffffffffff 0xff
{27BDA07D-2CC7-4F82-BC7A-A2F448AB430F} 0xffffffffffffffff 0xff
{15DE6EAF-EE08-4DE7-9A1C-BC7534AB8465} 0xffffffffffffffff 0xff
{31332297-E093-4B25-A489-BC9194116265} 0xffffffffffffffff 0xff
{4fcbf664-a33a-4652-b436-9d558983d955} 0xffffffffffffffff 0xff
{DBA0E0E0-505A-4AB6-AA3F-22F6F743B480} 0xffffffffffffffff 0xff
{125f2cf1-2768-4d33-976e-527137d080f8} 0xffffffffffffffff 0xff
{beffb691-61cc-4879-9cd9-ede744f6d618} 0xffffffffffffffff 0xff
{545c1f45-614a-4c72-93a0-9535ac05c554} 0xffffffffffffffff 0xff
{AEDD909F-41C6-401A-9E41-DFC33006AF5D} 0xffffffffffffffff 0xff
{09AC07B9-6AC9-43BC-A50F-58419A797C69} 0xffffffffffffffff 0xff
{AAEAC398-3028-487C-9586-44EACAD03637} 0xffffffffffffffff 0xff
{9F650C63-9409-453C-A652-83D7185A2E83} 0xffffffffffffffff 0xff
{F5DBD783-410E-441C-BD12-7AFB63C22DA2} 0xffffffffffffffff 0xff
{a3c09ba3-2f62-4be5-a50f-8278a646ac9d} 0xffffffffffffffff 0xff
{15f92702-230e-4d49-9267-8e25ae03047c} 0xffffffffffffffff 0xff
{179f04fd-cf7a-41a6-9587-a3d22d5e39b0} 0xffffffffffffffff 0xff
'@
<#
    '{30EAE751-411F-414C-988B-A8BFA8913F49}!0xffffffffffffffff'
    '{13038E47-FFEC-425D-BC69-5707708075FE}!0xffffffffffffffff'
    '{3FCE7C5F-FB3B-4BCE-A9D8-55CC0CE1CF01}!0xffffffffffffffff'
    '{FB36CAF4-582B-4604-8841-9263574C4F2C}!0xffffffffffffffff'
    '{133A980D-035D-4E2D-B250-94577AD8FCED}!0xffffffffffffffff'
    '{EED7F3C9-62BA-400E-A001-658869DF9A91}!0xffffffffffffffff'
    '{27BDA07D-2CC7-4F82-BC7A-A2F448AB430F}!0xffffffffffffffff'
    '{15DE6EAF-EE08-4DE7-9A1C-BC7534AB8465}!0xffffffffffffffff'
    '{31332297-E093-4B25-A489-BC9194116265}!0xffffffffffffffff'
    '{4fcbf664-a33a-4652-b436-9d558983d955}!0xffffffffffffffff'
    '{DBA0E0E0-505A-4AB6-AA3F-22F6F743B480}!0xffffffffffffffff'
    '{125f2cf1-2768-4d33-976e-527137d080f8}!0xffffffffffffffff'
    '{beffb691-61cc-4879-9cd9-ede744f6d618}!0xffffffffffffffff'
    '{545c1f45-614a-4c72-93a0-9535ac05c554}!0xffffffffffffffff'
    '{AEDD909F-41C6-401A-9E41-DFC33006AF5D}!0xffffffffffffffff'
    '{09AC07B9-6AC9-43BC-A50F-58419A797C69}!0xffffffffffffffff'
    '{AAEAC398-3028-487C-9586-44EACAD03637}!0xffffffffffffffff'
    '{9F650C63-9409-453C-A652-83D7185A2E83}!0xffffffffffffffff'
    '{F5DBD783-410E-441C-BD12-7AFB63C22DA2}!0xffffffffffffffff'
    '{a3c09ba3-2f62-4be5-a50f-8278a646ac9d}!0xffffffffffffffff'
    '{15f92702-230e-4d49-9267-8e25ae03047c}!0xffffffffffffffff'
    '{179f04fd-cf7a-41a6-9587-a3d22d5e39b0}!0xffffffffffffffff'
#>
#=================================================== SMART_CARD_Providers ===================================================

#=================================================== CRED_PROVIDERS_Providers ===================================================
$CRED_PROVIDERS_Providers=
@'
{5e85651d-3ff2-4733-b0a2-e83dfa96d757} 0xffffffffffffffff 0xff
{D9F478BB-0F85-4E9B-AE0C-9343F302F9AD} 0xffffffffffffffff 0xff
{462a094c-fc89-4378-b250-de552c6872fd} 0xffffffffffffffff 0xff
{8db3086d-116f-5bed-cfd5-9afda80d28ea} 0xffffffffffffffff 0xff
{a55d5a23-1a5b-580a-2be5-d7188f43fae1} 0xFFFF 0xff
{4b8b1947-ae4d-54e2-826a-1aee78ef05b2} 0xFFFF 0xff
{176CD9C5-C90C-5471-38BA-0EEB4F7E0BD0} 0xffffffffffffffff 0xff
{3EC987DD-90E6-5877-CCB7-F27CDF6A976B} 0xffffffffffffffff 0xff
{41AD72C3-469E-5FCF-CACF-E3D278856C08} 0xffffffffffffffff 0xff
{4F7C073A-65BF-5045-7651-CC53BB272DB5} 0xffffffffffffffff 0xff
{A6C5C84D-C025-5997-0D82-E608D1ABBBEE} 0xffffffffffffffff 0xff
{C0AC3923-5CB1-5E37-EF8F-CE84D60F1C74} 0xffffffffffffffff 0xff
{DF350158-0F8F-555D-7E4F-F1151ED14299} 0xffffffffffffffff 0xff
{FB3CD94D-95EF-5A73-B35C-6C78451095EF} 0xffffffffffffffff 0xff
{d451642c-63a6-11d7-9720-00b0d03e0347} 0xffffffffffffffff 0xff
{b39b8cea-eaaa-5a74-5794-4948e222c663} 0xffffffffffffffff 0xff
{dbe9b383-7cf3-4331-91cc-a3cb16a3b538} 0xffffffffffffffff 0xff
{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97} 0xffffffffffffffff 0xff
{5B4F9E61-4334-409F-B8F8-73C94A2DBA41} 0xffffffffffffffff 0xff
{a789efeb-fc8a-4c55-8301-c2d443b933c0} 0xffffffffffffffff 0xff
{301779e2-227d-4faf-ad44-664501302d03} 0xffffffffffffffff 0xff
{557D257B-180E-4AAE-8F06-86C4E46E9D00} 0xffffffffffffffff 0xff
{D33E545F-59C3-423F-9051-6DC4983393A8} 0xffffffffffffffff 0xff
{19D78D7D-476C-47B6-A484-285D1290A1F3} 0xffffffffffffffff 0xff
{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98} 0xffffffffffffffff 0xff
{D9391D66-EE23-4568-B3FE-876580B31530} 0xffffffffffffffff 0xff
{D138F9A7-0013-46A6-ADCC-A3CE6C46525F} 0xffffffffffffffff 0xff
{2955E23C-4E0B-45CA-A181-6EE442CA1FC0} 0xffffffffffffffff 0xff
{012616AB-FF6D-4503-A6F0-EFFD0523ACE6} 0xffffffffffffffff 0xff
{5A24FCDB-1CF3-477B-B422-EF4909D51223} 0xffffffffffffffff 0xff
{63D2BB1D-E39A-41B8-9A3D-52DD06677588} 0xffffffffffffffff 0xff
{4B812E8E-9DFC-56FC-2DD2-68B683917260} 0xffffffffffffffff 0xff
{169CC90F-317A-4CFB-AF1C-25DB0B0BBE35} 0xffffffffffffffff 0xff
{041afd1b-de76-48e9-8b5c-fade631b0dd5} 0xffffffffffffffff 0xff
{39568446-adc1-48ec-8008-86c11637fc74} 0xffffffffffffffff 0xff
{d1731de9-f885-4e1f-948b-76d52702ede9} 0xffffffffffffffff 0xff
{d5272302-4e7c-45be-961c-62e1280a13db} 0xffffffffffffffff 0xff
{55f422c8-0aa0-529d-95f5-8e69b6a29c98} 0xffffffffffffffff 0xff
'@
<#
    '{5e85651d-3ff2-4733-b0a2-e83dfa96d757}!0xffffffffffffffff'
    '{D9F478BB-0F85-4E9B-AE0C-9343F302F9AD}!0xffffffffffffffff'
    '{462a094c-fc89-4378-b250-de552c6872fd}!0xffffffffffffffff'
    '{8db3086d-116f-5bed-cfd5-9afda80d28ea}!0xffffffffffffffff'
    '{a55d5a23-1a5b-580a-2be5-d7188f43fae1}!0xFFFF'
    '{4b8b1947-ae4d-54e2-826a-1aee78ef05b2}!0xFFFF'
    '{176CD9C5-C90C-5471-38BA-0EEB4F7E0BD0}!0xffffffffffffffff'
    '{3EC987DD-90E6-5877-CCB7-F27CDF6A976B}!0xffffffffffffffff'
    '{41AD72C3-469E-5FCF-CACF-E3D278856C08}!0xffffffffffffffff'
    '{4F7C073A-65BF-5045-7651-CC53BB272DB5}!0xffffffffffffffff'
    '{A6C5C84D-C025-5997-0D82-E608D1ABBBEE}!0xffffffffffffffff'
    '{C0AC3923-5CB1-5E37-EF8F-CE84D60F1C74}!0xffffffffffffffff'
    '{DF350158-0F8F-555D-7E4F-F1151ED14299}!0xffffffffffffffff'
    '{FB3CD94D-95EF-5A73-B35C-6C78451095EF}!0xffffffffffffffff'
    '{d451642c-63a6-11d7-9720-00b0d03e0347}!0xffffffffffffffff'
    '{b39b8cea-eaaa-5a74-5794-4948e222c663}!0xffffffffffffffff'
    if (!$slowlogon) { '{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}!0xffffffffffffffff' } << Included
    '{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97}!0xffffffffffffffff'
    '{5B4F9E61-4334-409F-B8F8-73C94A2DBA41}!0xffffffffffffffff'
    '{a789efeb-fc8a-4c55-8301-c2d443b933c0}!0xffffffffffffffff'
    '{301779e2-227d-4faf-ad44-664501302d03}!0xffffffffffffffff'
    '{557D257B-180E-4AAE-8F06-86C4E46E9D00}!0xffffffffffffffff'
    '{D33E545F-59C3-423F-9051-6DC4983393A8}!0xffffffffffffffff'
    '{19D78D7D-476C-47B6-A484-285D1290A1F3}!0xffffffffffffffff'
    '{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}!0xffffffffffffffff'
    '{D9391D66-EE23-4568-B3FE-876580B31530}!0xffffffffffffffff'
    '{D138F9A7-0013-46A6-ADCC-A3CE6C46525F}!0xffffffffffffffff'
    '{2955E23C-4E0B-45CA-A181-6EE442CA1FC0}!0xffffffffffffffff'
    '{012616AB-FF6D-4503-A6F0-EFFD0523ACE6}!0xffffffffffffffff'
    '{5A24FCDB-1CF3-477B-B422-EF4909D51223}!0xffffffffffffffff'
    '{63D2BB1D-E39A-41B8-9A3D-52DD06677588}!0xffffffffffffffff'
    '{4B812E8E-9DFC-56FC-2DD2-68B683917260}!0xffffffffffffffff'
    '{169CC90F-317A-4CFB-AF1C-25DB0B0BBE35}!0xffffffffffffffff'
    '{041afd1b-de76-48e9-8b5c-fade631b0dd5}!0xffffffffffffffff'
    '{39568446-adc1-48ec-8008-86c11637fc74}!0xffffffffffffffff'
    '{d1731de9-f885-4e1f-948b-76d52702ede9}!0xffffffffffffffff'
    '{d5272302-4e7c-45be-961c-62e1280a13db}!0xffffffffffffffff'
    '{55f422c8-0aa0-529d-95f5-8e69b6a29c98}!0xffffffffffffffff'
#>
#=================================================== CRED_PROVIDERS_Providers ===================================================

#=================================================== APPX_Providers ===================================================
$APPX_Providers=
@'
{f0be35f8-237b-4814-86b5-ade51192e503} 0xffffffffffffffff 0xff
{8127F6D4-59F9-4abf-8952-3E3A02073D5F} 0xffffffffffffffff 0xff
{3ad13c53-cf84-4522-b349-56b81ffcd939} 0xffffffffffffffff 0xff
{b89fa39d-0d71-41c6-ba55-effb40eb2098} 0xffffffffffffffff 0xff
{fe762fb1-341a-4dd4-b399-be1868b3d918} 0xffffffffffffffff 0xff
'@
<#
    '{f0be35f8-237b-4814-86b5-ade51192e503}!0xffffffffffffffff'
    '{8127F6D4-59F9-4abf-8952-3E3A02073D5F}!0xffffffffffffffff'
    '{3ad13c53-cf84-4522-b349-56b81ffcd939}!0xffffffffffffffff'
    '{b89fa39d-0d71-41c6-ba55-effb40eb2098}!0xffffffffffffffff'
    '{fe762fb1-341a-4dd4-b399-be1868b3d918}!0xffffffffffffffff'
#>
#=================================================== APPX_Providers ===================================================



####################################################
#                All Functions
####################################################
Function Wait_for_User
{
    Write-Host "`nPress Enter key to stop logging.....`n" -ForegroundColor Yellow
    Read-Host

    # Recored the end time of script
    "End at "+(Get-Date) | Out-File -FilePath $global:full_script_logs_folder -Append
}


####################################################
#                Functions at start
####################################################
Function Create_Log_Folder
{
    # Creating folder for logs of thie script
    $global:full_script_logs_folder = $global:full_folder+"\Logs_of_script\"
    If (!(Test-Path $global:full_script_logs_folder))
    {
        If ($global:verbose_output){Write-Host "Creating Folder" $global:full_folder -ForegroundColor Red}
        New-Item -Path $global:full_script_logs_folder -ItemType Directory | Out-Null
    }
    If ($global:verbose_output){Write-Host $global:full_script_logs_folder" exsited" -ForegroundColor Red}
    $global:full_script_logs_folder = $global:full_script_logs_folder+"script_time_logs.txt"
    $start_time = "Start at " 
    $start_time += Get-Date
    $start_time | Out-File -FilePath $global:full_script_logs_folder
    
    # Creating event logs folder
    $global:full_eventlog_folder = $global:full_folder+"\Event_Logs\"
    If (!(Test-Path $global:full_eventlog_folder))
    {
        If ($global:verbose_output){Write-Host "Creating Folder" $global:full_folder -ForegroundColor Red}
        New-Item -Path $global:full_eventlog_folder -ItemType Directory | Out-Null
    }
    If ($global:verbose_output){Write-Host $global:full_eventlog_folder" exsited" -ForegroundColor Red}

    # Creating registry info folder
    $global:full_reg_folder = $global:full_folder+"\Registry\"
    If (!(Test-Path $global:full_reg_folder))
    {
        If ($global:verbose_output){Write-Host "Creating Folder" $global:full_folder -ForegroundColor Red}
        New-Item -Path $global:full_reg_folder -ItemType Directory | Out-Null
    }
    If ($global:verbose_output){Write-Host $global:full_eventlog_folder" exsited" -ForegroundColor Red}

    # Creating certificate folder
    $global:full_cert_folder = $global:full_folder+"\Certificates\"
    If (!(Test-Path $global:full_cert_folder))
    {
        If ($global:verbose_output){Write-Host "Creating Folder" $global:full_folder -ForegroundColor Red}
        New-Item -Path $global:full_cert_folder -ItemType Directory | Out-Null
    }
    If ($global:verbose_output){Write-Host $global:full_eventlog_folder" exsited" -ForegroundColor Red}

    # Creating net info and net trace folder
    $global:full_net_folder = $global:full_folder+"\Network\"
    If (!(Test-Path $global:full_net_folder))
    {
        If ($global:verbose_output){Write-Host "Creating Folder" $global:full_folder -ForegroundColor Red}
        New-Item -Path $global:full_net_folder -ItemType Directory | Out-Null
    }

    # Creating WAM folder
    $global:full_wam_folder = $global:full_folder+"\WAM\"
    If (!(Test-Path $global:full_wam_folder))
    {
        If ($global:verbose_output){Write-Host "Creating Folder" $global:full_folder -ForegroundColor Red}
        New-Item -Path $global:full_wam_folder -ItemType Directory | Out-Null
    }

    # Creating ETW logs folder
    $global:full_etw_folder = $global:full_folder+"\ETW\"
    If (!(Test-Path $global:full_etw_folder))
    {
        If ($global:verbose_output){Write-Host "Creating Folder" $global:full_folder -ForegroundColor Red}
        New-Item -Path $global:full_etw_folder -ItemType Directory | Out-Null
    }
}


Function Start_PSR
{
    Write-Host " Starting PSR log.....`n" -ForegroundColor Blue
    psr.exe /start /output $global:full_folder"\psr.zip" /gui 0 /sc 1 /maxsc 100
}


Function Enable_Start_Event_Logs
{
    Write-Host " Starting all event logs.....`n" -ForegroundColor Blue
    If ($global:verbose_output){Write-Host "WE are in Start_Event_Logs" -ForegroundColor Red}

    foreach ($each_log in $global:event_list)
    {
        $each_log_settings = Get-WinEvent -ListLog $each_log

        if($each_log_settings.IsEnabled -eq $false)
        {
            #Write-Host $each_log "is disable and we are enabling it"
            $global:event_log_disabled_by_default += $each_log

            if($each_log.Contains("CAPI2"))
            {
                If ($global:verbose_output){Write-Host "Enabling $each_log, Change size and the original log size is" $each_log_settings.MaximumSizeInBytes -ForegroundColor Red}
                $global:CAPI2_Default_Size = $each_log_settings.MaximumSizeInBytes
                wevtutil.exe set-log $each_log /enabled:true /ms:102400000 /q:true
            }
            else
            {
                If ($global:verbose_output){Write-Host "Enabling" $each_log -ForegroundColor Red}
                wevtutil.exe set-log $each_log /enabled:true /q:true
            }
        }
        else
        {
            If ($global:verbose_output){Write-Host $each_log "is enabled" -ForegroundColor Red}

            if($each_log.Contains("CAPI2"))
            {
                If ($global:verbose_output){Write-Host "Change size of $each_log logs and the original log size is" $each_log_settings.MaximumSizeInBytes -ForegroundColor Red}
                $global:CAPI2_Default_Size = $each_log_settings.MaximumSizeInBytes
                wevtutil.exe set-log $each_log /ms:102400000 /q:true
            }
            elseif ($each_log.Contains("Analytic") -or $each_log.Contains("User Device Registration/Debug"))
            {
                If ($global:verbose_output){Write-Host "Disable $each_log log, backup the log and enable the log." -ForegroundColor Red}
                
                # Create file name for back up
                $file_name = $each_log.Replace(" ", "_").Replace("/","_")
                $event_file_path = $global:full_eventlog_folder+$file_name+"_backup.evtx"

                # Disable the log, save for backup and enable the log
                wevtutil.exe set-log $each_log /enabled:false /q:true | Out-Null
                wevtutil.exe export-log $each_log $event_file_path /overwrite:true | Out-Null

                # Enable the log
                wevtutil.exe set-log $each_log /enabled:true /q:true
            }
        }
    }
}


Function Start_ETW_Traces
{
    If ($global:verbose_output){Write-Host "We are starting all ETW logs....." -ForegroundColor Red}
    Write-Host " Starting all ETW logs.....`n" -ForegroundColor Blue
    
    #================================ WAM ETW ================================
    $providerFile_WAM = Join-Path $global:full_etw_folder -ChildPath "wam.txt"
    Set-Content -LiteralPath $providerFile_WAM -Value $WAM_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_WAM = Join-Path $global:full_etw_folder -ChildPath "WAM.etl"
    
    logman.exe start trace "WAM_Trace" -pf $providerFile_WAM -o $traceFile_WAM -ets | Out-Null
    If ($global:verbose_output){Write-Host "WAM_Trace started....." -ForegroundColor Red}    
    #================================ WAM ETW ================================

    #================================ NGC ETW ================================
    $providerFile_NGC = Join-Path $global:full_etw_folder -ChildPath "NGC.txt"
    Set-Content -LiteralPath $providerFile_NGC -Value $NGC_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_NGC = Join-Path $global:full_etw_folder -ChildPath "NGC.etl"
    
    logman.exe start trace "NGC_Trace" -pf $providerFile_NGC -o $traceFile_NGC -ets | Out-Null
    If ($global:verbose_output){Write-Host "NGC_Trace started....." -ForegroundColor Red}
    #================================ NGC ETW ================================

    #================================ BIOM ETW ================================
    $providerFile_BIOM = Join-Path $global:full_etw_folder -ChildPath "BIOM.txt"
    Set-Content -LiteralPath $providerFile_BIOM -Value $BIOM_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_BIOM = Join-Path $global:full_etw_folder -ChildPath "Biometric.etl"
    
    logman.exe start trace "BIOM_Trace" -pf $providerFile_BIOM -o $traceFile_BIOM -ets | Out-Null
    If ($global:verbose_output){Write-Host "BIOM_Trace started....." -ForegroundColor Red}
    #================================ BIOM ETW ================================
    
    #================================ LSA ETW ================================
    $providerFile_LSA = Join-Path $global:full_etw_folder -ChildPath "LSA.txt"
    Set-Content -LiteralPath $providerFile_LSA -Value $LSA_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_LSA = Join-Path $global:full_etw_folder -ChildPath "LSA.etl"
    
    logman.exe start trace "LSA_Trace" -pf $providerFile_LSA -o $traceFile_LSA -ets | Out-Null
    If ($global:verbose_output){Write-Host "LSA_Trace started....." -ForegroundColor Red}
    
    #================================ LSA ETW ================================

    #================================ NTLM ETW ================================
    $providerFile_NTLM = Join-Path $global:full_etw_folder -ChildPath "NTLM.txt"
    Set-Content -LiteralPath $providerFile_NTLM -Value $NTLM_Prodivers -Encoding Ascii -ErrorAction Stop
    $traceFile_NTLM = Join-Path $global:full_etw_folder -ChildPath "NTLM.etl"
    
    logman.exe start trace "NTLM_Trace" -pf $providerFile_NTLM -o $traceFile_NTLM -ets | Out-Null
    If ($global:verbose_output){Write-Host "NTLM_Trace started....." -ForegroundColor Red}
    #================================ NTLM ETW ================================ 

    #================================ KRB ETW ================================
    $providerFile_KRB = Join-Path $global:full_etw_folder -ChildPath "Kerberos.txt"
    Set-Content -LiteralPath $providerFile_KRB  -Value $KRB_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_KRB = Join-Path $global:full_etw_folder -ChildPath "Kerberos.etl"
    
    logman.exe start trace "KRB_Trace" -pf $providerFile_KRB  -o $traceFile_KRB -ets | Out-Null
    If ($global:verbose_output){Write-Host "KRB_Trace started....." -ForegroundColor Red}
    #================================ KRB ETW ================================ 
    
    #================================ KDC ETW ================================
    $providerFile_KDC = Join-Path $global:full_etw_folder -ChildPath "KDC.txt"
    Set-Content -LiteralPath $providerFile_KDC  -Value $KDC_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_KDC = Join-Path $global:full_etw_folder -ChildPath "KDC.etl"
    
    logman.exe start trace "KDC_Trace" -pf $providerFile_KDC  -o $traceFile_KDC -ets | Out-Null
    If ($global:verbose_output){Write-Host "KDC_Trace started....." -ForegroundColor Red}
    #================================ KDC ETW ================================ 

    #================================ SAM ETW ================================
    $providerFile_SAM = Join-Path $global:full_etw_folder -ChildPath "SAM.txt"
    Set-Content -LiteralPath $providerFile_SAM  -Value $SAM_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_SAM = Join-Path $global:full_etw_folder -ChildPath "SAM.etl"
    
    logman.exe start trace "SAM_Trace" -pf $providerFile_SAM  -o $traceFile_SAM -ets | Out-Null
    If ($global:verbose_output){Write-Host "SAM_Trace started....." -ForegroundColor Red}
    #================================ SAM ETW ================================ 

    #================================ SSL ETW ================================
    $providerFile_SSL = Join-Path $global:full_etw_folder -ChildPath "SSL.txt"
    Set-Content -LiteralPath $providerFile_SSL  -Value $SSL_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_SSL = Join-Path $global:full_etw_folder -ChildPath "SSL.etl"
    
    logman.exe start trace "SSL_Trace" -pf $providerFile_SSL  -o $traceFile_SSL -ets | Out-Null
    If ($global:verbose_output){Write-Host "SSL_Trace started....." -ForegroundColor Red}
    #================================ SSL ETW ================================ 

    #================================ CRYPT ETW ================================
    $providerFile_CRYPT = Join-Path $global:full_etw_folder -ChildPath "CRYPT.txt"
    Set-Content -LiteralPath $providerFile_CRYPT  -Value $CRYPT_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_CRYPT = Join-Path $global:full_etw_folder -ChildPath "CRYPT.etl"
    
    logman.exe start trace "CRYPT_Trace" -pf $providerFile_CRYPT  -o $traceFile_CRYPT -ets | Out-Null
    If ($global:verbose_output){Write-Host "CRYPT_Trace started....." -ForegroundColor Red}
    #================================ CRYPT ETW ================================ 

    #================================ SMART ETW ================================
    $providerFile_SMART = Join-Path $global:full_etw_folder -ChildPath "SMART.txt"
    Set-Content -LiteralPath $providerFile_SMART  -Value $SMART_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_SMART = Join-Path $global:full_etw_folder -ChildPath "SMART.etl"
    
    logman.exe start trace "SMART_Trace" -pf $providerFile_SMART  -o $traceFile_SMART -ets | Out-Null
    If ($global:verbose_output){Write-Host "SMART_Trace started....." -ForegroundColor Red}
    #================================ SMART ETW ================================ 

    #================================ CRED PROVIDERs ETW ================================
    $providerFile_CRED = Join-Path $global:full_etw_folder -ChildPath "CRED.txt"
    Set-Content -LiteralPath $providerFile_CRED  -Value $CRED_PROVIDERS_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_CRED = Join-Path $global:full_etw_folder -ChildPath "CRED.etl"
    
    logman.exe start trace "CRED_Trace" -pf $providerFile_CRED  -o $traceFile_CRED -ets | Out-Null
    If ($global:verbose_output){Write-Host "CRED_Trace started....." -ForegroundColor Red}
    #================================ CRED PROVIDERs ETW ================================ 

    #================================ APPX ETW ================================
    $providerFile_APPX = Join-Path $global:full_etw_folder -ChildPath "APPX.txt"
    Set-Content -LiteralPath $providerFile_APPX  -Value $APPX_Providers -Encoding Ascii -ErrorAction Stop
    $traceFile_APPX = Join-Path $global:full_etw_folder -ChildPath "APPX.etl"
    
    logman.exe start trace "APPX_Trace" -pf $providerFile_APPX  -o $traceFile_APPX -ets | Out-Null
    If ($global:verbose_output){Write-Host "APPX_Trace started....." -ForegroundColor Red}
    #================================ APPX ETW ================================
}


Function Start_Network_Trace
{
    Write-Host " Starting network trace.....`n" -ForegroundColor Blue
    If ($global:verbose_output){Write-Host "We are starting network trace." -ForegroundColor Red}
    netsh trace start capture=yes scenario=InternetClient_dbg maxsize=4096 tracefile=$global:full_net_folder"Network_Trace.etl" | Out-Null
}


####################################################
#                Functions at end
####################################################
Function Stop_NetTrace_Get_NetInfo
{
    If ($global:verbose_output){Write-Host "We are stopping network trace..." -ForegroundColor Red}
    Write-Host " Stopping network trace and collecting network related information...`n" -ForegroundColor Blue

    #Stopping nertwork trace
    netsh trace stop | Out-Null

    # Geting result of network connectivity
    # 2023/4/14 Change from RemoteSigned to Bypass
    Powershell.exe -ExecutionPolicy Bypass -File $global:current_Folder"\Test-DeviceRegConnectivity.ps1" | Out-File -FilePath $global:full_net_folder"Test_DeviceRegConnectivity_Output.txt" 2>&1 | Out-Null
    Copy-Item $global:current_Folder"\Test-DeviceRegConnectivity.log" -Destination $global:full_net_folder | Out-Null
    Remove-Item $global:current_Folder"\Test-DeviceRegConnectivity.log" -Force  | Out-Null
    
    #.\Test-DeviceRegConnectivity.ps1 | Out-Null
    #Move-Item $global:current_Folder"\Test-DeviceRegConnectivity.log" -Destination $global:full_net_folder | Out-Null
    
    # WinhTTP Proxy
    netsh winhttp show proxy > $global:full_net_folder"winhttp_proxy.txt" 2>&1 | Out-Null

    # WinINet
    # 2023/7/13 Move this to user context
    #reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /s > $global:full_net_folder"REG_WinINet01.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /s > $global:full_net_folder"REG_WinINet02.txt" 2>&1 | Out-Null

    # ipconfig
    ipconfig /all > $global:full_net_folder"IPCofig_ALL.txt" 2>&1 | Out-Null
    ipconfig /displayDNS > $global:full_net_folder"IPCofig_Display_DNS.txt" 2>&1 | Out-Null

    # netstat
    netstat -anoi > $global:full_net_folder"netstat_anoi.txt" 2>&1 | Out-Null
    netstat -r > $global:full_net_folder"netstat_routingTable.txt" 2>&1 | Out-Null

    # bitsadmin proxy of system, networkservice and localservice
    bitsadmin /util /getieproxy LOCALSYSTEM > $global:full_net_folder"LOCAL_SYSTEM_proxy.txt" 2>&1 | Out-Null
    bitsadmin /util /getieproxy NETWORKSERVICE > $global:full_net_folder"NETWORK_SERVICE_proxy.txt" 2>&1 | Out-Null
    bitsadmin /util /getieproxy LOCALSERVICE > $global:full_net_folder"LOCAL_SERVICE_proxy.txt" 2>&1 | Out-Null
}


function Stop_ETW_Trace 
{
    If ($global:verbose_output){Write-Host "We are in Stop_WAM_Trace...." -ForegroundColor Red}
    Write-Host " Stopping and collecting ETW logs.....`n" -ForegroundColor Blue

    logman stop "WAM_Trace" -ets | Out-Null
    #Write-Host "WAM_Trace stopped....."
    logman stop "NGC_Trace" -ets | Out-Null
    #Write-Host "NGC_Trace stopped....."
    logman stop "BIOM_Trace" -ets | Out-Null
    #Write-Host "BIOM_Trace stopped....."
    logman stop "LSA_Trace" -ets | Out-Null
    #Write-Host "LSA_Trace stopped....."
    logman stop "NTLM_Trace" -ets | Out-Null
    #Write-Host "NTLM_Trace stopped....."
    logman stop "KRB_Trace" -ets | Out-Null
    #Write-Host "KRB_Trace stopped....."
    logman stop "KDC_Trace" -ets | Out-Null
    #Write-Host "KDC_Trace stopped....."
    logman stop "SAM_Trace" -ets | Out-Null
    #Write-Host "SAM_Trace stopped....."
    logman stop "SSL_Trace" -ets | Out-Null
    #Write-Host "SSL_Trace stopped....."
    logman stop "CRYPT_Trace" -ets | Out-Null
    #Write-Host "CRYPT_Trace stopped....."
    logman stop "SMART_Trace" -ets | Out-Null
    #Write-Host "SMART_Trace stopped....."
    logman stop "CRED_Trace" -ets | Out-Null
    #Write-Host "CRED_Trace stopped....."
    logman stop "APPX_Trace" -ets | Out-Null
    #Write-Host "APPX_Trace stopped....."
}


Function Stop_Event_Logs
{
    If ($global:verbose_output){Write-Host "We are in Stop_Event_Logs" -ForegroundColor Red}
    Write-Host " Stopping and collecting Event logs...`n" -ForegroundColor Blue

    foreach ($each_log in $global:event_list)
    {
        $file_name = $each_log.Replace(" ", "_").Replace("/","_")
        $event_file_path = $global:full_eventlog_folder+$file_name+".evtx"

        if ($global:event_log_disabled_by_default.Contains($each_log))
        {
            if ($each_log.Contains("CAPI2"))
            {
                If ($global:verbose_output){Write-Host "Saving CAPI2 to" $event_file_path ", change size back to" $global:CAPI2_Default_Size ",and disable it" -ForegroundColor Red}
                wevtutil.exe set-log $each_log /enabled:false /ms:$global:CAPI2_Default_Size /q:true | Out-Null
                wevtutil.exe export-log $each_log $event_file_path /overwrite:true | Out-Null
            }
            else
            {
                If ($global:verbose_output){Write-Host "Disabling" $each_log "and save to" $event_file_path -ForegroundColor Red}
                wevtutil.exe set-log $each_log /enabled:false /q:true | Out-Null
                wevtutil.exe export-log $each_log $event_file_path /overwrite:true | Out-Null
            }
        }
        else
        {
            if ($each_log.Contains("CAPI2"))
            {
                If ($global:verbose_output){Write-Host "Saving CAPI2 to" $event_file_path ", change size back to" $global:CAPI2_Default_Size -ForegroundColor Red}
                wevtutil.exe set-log $each_log /ms:$global:CAPI2_Default_Size /q:true | Out-Null
                wevtutil.exe export-log $each_log $event_file_path /overwrite:true | Out-Null
            }
            elseif ($each_log.Contains("Analytic") -or $each_log.Contains("User Device Registration/Debug"))
            {
                If ($global:verbose_output){Write-Host "Disabling $each_log log, save the log and enable the log." -ForegroundColor Red}

                # Disable the log, save the log and enable the log
                wevtutil.exe set-log $each_log /enabled:false /q:true | Out-Null
                wevtutil.exe export-log $each_log $event_file_path /overwrite:true | Out-Null

                # Enable the log again
                wevtutil.exe set-log $each_log /enabled:true /q:true
            }
            else
            {
                if ($global:verbose_output){Write-Host "$each_log is enabled and save to" $event_file_path -ForegroundColor Red}
                wevtutil.exe export-log $each_log $event_file_path /overwrite:true | Out-Null
            }
        }
    }

    wevtutil.exe epl System $global:full_eventlog_folder"System_Event_Logs.evtx" | Out-Null
    wevtutil.exe epl Application $global:full_eventlog_folder"Application_Event_Logs.evtx" | Out-Null
    wevtutil.exe epl Security $global:full_eventlog_folder"Security_Event_Logs.evtx" | Out-Null
}


# Gathering information from registry keys
Function Get_Reg
{
    If ($global:verbose_output){Write-Host "Entering Get-Reg" -ForegroundColor Red}

    # Getting build info
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildLabEx > $global:full_reg_folder"HKLM_BUILD_VERSION.txt" 2>&1 | Out-Null

    # Getting information
    # HKLM
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication" /s > $global:full_reg_folder"HKLM_authentication.txt" 2>&1 | Out-Null
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio" /s > $global:full_reg_folder"HKLM_winbio.txt" 2>&1 | Out-Null
    reg query "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /s > $global:full_reg_folder"HKLM_wbiosrvc.txt" 2>&1 | Out-Null
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\EAS\Policies" /s > $global:full_reg_folder"HKLM_eas.txt" 2>&1 | Out-Null
    reg query "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /s > $global:full_reg_folder"HKLM_policies.txt" 2>&1 | Out-Null
    reg query "HKLM\SOFTWARE\Microsoft\SQMClient" /s > $global:full_reg_folder"HKLM_MachineId.txt" 2>&1 | Out-Null
    reg query "HKLM\SOFTWARE\Microsoft\Policies\PassportForWork" /s > $global:full_reg_folder"HKLM_NgcPolicyIntune.txt" 2>&1 | Out-Null
    reg query "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /s > $global:full_reg_folder"HKLM_NgcPolicyGp.txt" 2>&1 | Out-Null
    reg query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" /s > $global:full_reg_folder"HKLM_DeviceLockPolicy.txt" 2>&1 | Out-Null
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin" /s > $global:full_reg_folder"HKLM_CloudDomainJoin.txt" 2>&1 | Out-Null
    reg query "HKLM\Software\Microsoft\IdentityStore" /s > $global:full_reg_folder"HKLM_idstore_config.txt" 2>&1 | Out-Null
    reg query "HKLM\Software\Microsoft\IdentityCRL" /s > $global:full_reg_folder"HKLM_IdentityCRL.txt" 2>&1 | Out-Null
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TokenBroker" /s > $global:full_reg_folder"HKLM_TOkenBroker.txt" 2>&1 | Out-Null
    reg query "HKLM\Software\Microsoft\Enrollments" /s > $global:full_reg_folder"HKLM_Enrollments.txt" 2>&1 | Out-Null
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" /s > $global:full_reg_folder"HKLM_pku2u.txt" 2>&1 | Out-Null
    reg query "HKLM\Software\Policies\Microsoft\Windows\WorkplaceJoin" /s > $global:full_reg_folder"HKLM_WPJ_GPO.txt" 2>&1 | Out-Null

    # HKU
    reg query "HKEY_USERS\.Default\Software\Microsoft\IdentityCRL" /s >> $global:full_reg_folder"HKU_idstore_config.txt" 2>&1 | Out-Null

    # HKCU
    # 2023/7/13 Move to user context
    #reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin" /s > $global:full_reg_folder"HKCU_WPJ.txt" 2>&1 | Out-Null
    #reg query "HKCU\SOFTWARE\Microsoft\SCEP" /s > $global:full_reg_folder"HKCU_scep.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Microsoft\IdentityCRL" /s > $global:full_reg_folder"HKCU_IdentityCRL.txt" 2>&1 | Out-Null
    #reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TokenBroker" /s > $global:full_reg_folder"HKCU_TokenBroker.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.aad.brokerplugin_cw5n1h2txyewy" /s > $global:full_reg_folder"HKCU_AAD_BrokerPlugIn.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /s > $global:full_reg_folder"HKCU_ContentDeliveryManager.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Microsoft\AuthCookies" /s > $global:full_reg_folder"HKCU_AuthCookies.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\AAD" /s > $global:full_reg_folder"HKCU_AAD.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /s > $global:full_reg_folder"HKCU_PushNotifications.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\ActivityDataModel" /s > $global:full_reg_folder"HKCU_ActivityDataModel.txt" 2>&1 | Out-Null
    #reg query "HKCU\Software\Classes\Local Settings\MrtCache" /s > $global:full_reg_folder"HKCU_MrtCache.txt" 2>&1 | Out-Null
    #reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AAD" /s > $global:full_reg_folder"HKCU_AAD.txt" 2>&1 | Out-Null

    If ($global:verbose_output){Write-Host "Exiting Get-Reg" -ForegroundColor Red}
}


# Gathering certificate information
Function Get_Certs
{
    If ($global:verbose_output){Write-Host "Entering Get_Certs" -ForegroundColor Red}

    certutil -v -silent -store ROOT > $global:full_cert_folder"CERT_Root.txt" 2>&1 | Out-Null
    certutil -v -silent -store -user ROOT > $global:full_cert_folder"CERT_Root_User.txt" 2>&1 | Out-Null
    certutil -v -silent -store CA > $global:full_cert_folder"CERT_CA.txt" 2>&1 | Out-Null
    certutil -v -silent -store AUTHROOT > $global:full_cert_folder"CERT_AUTHROOT.txt" 2>&1 | Out-Null
    certutil -v -silent -store -enterprise ROOT > $global:full_cert_folder"CERT_Enterprise_Root.txt" 2>&1 | Out-Null
    certutil -v -silent -store -enterprise NTAUTH > $global:full_cert_folder"CERT_Enterprise_NTAuth.txt" 2>&1 | Out-Null
    certutil -v -silent -store -grouppolicy ROOT > $global:full_cert_folder"CERT_GPO_ROOT.txt" 2>&1 | Out-Null
    certutil -v -silent -store MY > $global:full_cert_folder"CERT_Machine_MY.txt" 2>&1 | Out-Null
    certutil -v -silent -store -user MY > $global:full_cert_folder"CERT_User_MY.txt" 2>&1 | Out-Null
    certutil -v -silent -scinfo > $global:full_cert_folder"CERT_smart_card_info.txt" 2>&1 | Out-Null # Displays information about the smart card.
    certutil -tpminfo > $global:full_cert_folder"CERT_TPM_Info.txt" 2>&1 | Out-Null
    certutil -v -silent -user -key -csp > $global:full_cert_folder"CERT_MS_Passport_Key.txt" 2>&1 | Out-Null
    certutil -v -silent -user -store my > $global:full_cert_folder"CERT_MS_Passport_Provider.txt" 2>&1 | Out-Null

    If ($global:verbose_output){Write-Host "Exiting Get_Certs" -ForegroundColor Red}
}

Function Get_SCP
{
    If ($global:verbose_output){Write-Host "Entering Get_SCP" -ForegroundColor Red}

    # Get local SCP info
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ" /s > $global:full_folder"\SCP_REG.txt" 2>&1 | Out-Null

    # Get SCP on AD
    $Root = [ADSI]"LDAP://RootDSE"
    $rootdn = $Root.rootDomainNamingContext
    if ($rootdn -ne $null)
    {
        $scp = New-Object System.DirectoryServices.DirectoryEntry
        $scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration,"+$rootdn
        #$scp.Keywords;
        $scp.Keywords | Out-File -FilePath $global:full_folder"\SCP_AD_User.txt" 2>&1 | Out-Null
    }
    else 
    {
        "Not able to query SCP on AD from here" | Out-File -FilePath $global:full_folder"\SCP_AD_Admin.txt" 2>&1 | Out-Null
    }
    If ($global:verbose_output){Write-Host "Exiting Get_SCP" -ForegroundColor Red}
}

Function Get_ALL_Other_INFO
{
    If ($global:verbose_output){Write-Host "Entering Get_ALL_Other_INFO" -ForegroundColor Red}

    #dsregcmd
    dsregcmd.exe /status > $global:full_folder"\dsregcmd_status_admin.txt" 2>&1 | Out-Null
    dsregcmd.exe /debug > $global:full_folder"\dsregcmd_debug_admin.txt" 2>&1 | Out-Null
    dsregcmd.exe /status_old > $global:full_folder"\dsregcmd_status_old_admin.txt" 2>&1 | Out-Null
    dsregcmd.exe /ListAccounts > $global:full_folder"\dsregcmd_ListAccounts_admin.txt" 2>&1 | Out-Null
    dsregcmd.exe /RunSystemTests > $global:full_folder"\dsregcmd_RunSystemTests_admin.txt" 2>&1 | Out-Null
   
    # GPO
    gpresult /V > $global:full_folder"\GPResult_V_admin.txt" 2>&1 | Out-Null
    gpresult /H $global:full_folder"\GPResult_H_admin.html" 2>&1 | OUt-Null
    
    # Credential Manager
    cmdkey.exe /list > $global:full_folder"\credman.txt" 2>&1 | Out-Null
    
    # klist
    klist.exe > $global:full_folder"\klist_admin.txt" 2>&1 | Out-Null
    klist.exe cloud_debug > $global:full_folder"\klist_cloud_debug_admin.txt" 2>&1 | Out-Null
    klist.exe tgt > $global:full_folder"\klist_tgt_admin.txt" 2>&1 | Out-Null
    klist.exe sessions > $global:full_folder"\klist_sessions_admin.txt" 2>&1 | Out-Null
    klist.exe kcd_cache > $global:full_folder"\klist_kcd_cache_admin.txt" 2>&1 | Out-Null
    klist.exe query_bind > $global:full_folder"\klist_query_bind_admin.txt" 2>&1 | Out-Null
    
    # QFE
    wmic qfe list > $global:full_folder"\qfes_installed.txt" 2>&1 | Out-Null

    # whoami
    whoami /UPN > $global:full_folder"\whoami_upn_admin.txt" 2>&1 | Out-Null
    whoami /ALL > $global:full_folder"\whoami_all_admin.txt" 2>&1 | Out-Null

    # Task scheduler
    schtasks /query > $global:full_folder"\schtasks_query.txt" 2>&1 | Out-Null
    If ($global:verbose_output){Write-Host "Exiting Get_ALL_Other_INFO" -ForegroundColor Red}

    # List of applications installed
    #winget list --accept-source-agreements > $global:full_folder"\apps_installed.txt" 2>&1 | Out-Null
    get-package | Select-Object Name,Version,Source,ProviderName | Out-File -FilePath $global:full_folder"\apps_installed.txt" 2>&1 | Out-Null

    # List of processes running
    tasklist /svc > $global:full_folder"\tasklist_svc.txt" 2>&1 | Out-Null
}

Function Stop_PSR
{
    psr.exe /stop
}

####################################################
#               Run All Functions
####################################################
Write-Host "`nPreparing for logging.....`n" -ForegroundColor Yellow
Create_Log_Folder;

Write-Host "Start collecting logs under user context...`n" -ForegroundColor Yellow
#Write-Host "We are starting PSR log.....`n" -ForegroundColor Blue
Start_PSR;

#Write-Host "We are starting all event logs.....`n" -ForegroundColor Blue
Enable_Start_Event_Logs;

#Write-Host "We are starting all ETW logs.....`n" -ForegroundColor Blue
Start_ETW_Traces;

#Write-Host "We are starting network trace.....`n" -ForegroundColor Blue
Start_Network_Trace;

# Wait for user to enter
Wait_for_User;

# Stop Logs
#Write-Host "We are stopping and collecting network trace.....This could take several minutes depends on the log size.`n" -ForegroundColor Blue
Stop_NetTrace_Get_NetInfo;

#Write-Host "We are stopping and collecting ETW logs.....`n" -ForegroundColor Blue
Stop_ETW_Trace;

#Write-Host "We are stopping and collecting Event logs.....`n" -ForegroundColor Blue
Stop_Event_Logs;

# Get all informations
Write-Host " Collecting all other information...`n" -ForegroundColor Blue
Get_Reg;
Get_Certs;
Get_SCP;
Get_ALL_Other_INFO;
#Write-Host "Done collecting all other information...`n" -ForegroundColor Blue

Write-Host " Stopping and collecing PSR log...`n" -ForegroundColor Blue
Stop_PSR;
#>

# Clean up variables
Write-Host "Cleaning up...`n" -ForegroundColor Yellow
Remove-Variable full_folder -Scope:global
Remove-Variable full_script_logs_folder -Scope:global
Remove-Variable full_eventlog_folder -Scope:global
Remove-Variable full_reg_folder -Scope:global
Remove-Variable full_cert_folder -Scope:global
Remove-Variable full_net_folder -Scope:global
Remove-Variable event_list -Scope:global
Remove-Variable event_log_disabled_by_default -Scope:global
Remove-Variable CAPI2_Default_Size -Scope:global
Remove-Variable full_etw_folder -Scope:global

Write-Host "Now you can close this window by entering 'Exit'.`n" -ForegroundColor Yellow
