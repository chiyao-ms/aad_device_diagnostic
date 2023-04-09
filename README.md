# aad_device_diagnostic

1. 本サイトの Code から　aad_device_diagnostic-main.zip をダウンロードし、事象が発生する端末に展開します。

2. ユーザー権限で PowerSehll を起動し、aad_device_diagnostic-main.zip を展開したいフォルダに移動します。

3. 以下を入力し、aad_log_user.ps1 スクリプトを実行します。

Powershell.exe -Executionpolicy ByPass .\aad_log_user.ps1

4. 現在のユーザーにはローカル管理者権限がある場合、UAC (ユーザーアカウント制御) のウィンドウが表示されますので、[はい] をクリックします。
現在のユーザーにはローカル管理者権限がない場合、UAC  (ユーザーアカウント制御) のウィンドウでローカル管理者権限の情報を入力し、[はい] をクリックします。

5.管理者権限で別の PowerShell ウィンドウが起動してきますので、現在のフォルダは aad_device_diagnostic-main.zip を展開したフォルダであることを確認します。
＊aad_device_diagnostic-main.zip を展開したフォルダではない場合、aad_device_diagnostic-main.zip を展開したフォルダに移動します。

6. 新しい PowerShell ウィンドウで以下のコマンドを実行し、

Powershell.exe -Executionpolicy Bypass .\aad_log_admin.ps1

7. 以下のメッセージが表示されましたら、手順 5 で起動した Powershell ウィンドウで "exit" を入力するか、または Powershell ウィンドウの右上の× (バツ) ボタンをクリックし、ウィンドウを閉じます。

-------------------------------
Now you can close this window by entering 'Exit'.
-------------------------------

8. ログ採取は引き続き手順 2 で起動した Powershell ウィンドウで継続します。

9. 以下のメッセージが表示されましたら、ログ採取は完了したことを示しますので、C:\AAD_Logs フォルダを .zip などに圧縮し、弊社まで送りください。

-------------------------------
Thank you for collecging logs.
Please compress [C:\AAD_Logs] folder and send us.
-------------------------------
![image](https://user-images.githubusercontent.com/28209857/230798252-c584247f-094f-42d6-810b-42391c6b476c.png)

