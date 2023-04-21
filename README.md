# aad_device_diagnostic

1. [ここ](https://github.com/jpazureid/aad_device_diagnostic/archive/refs/heads/main.zip) から aad_device_diagnostic-main.zip をダウンロードし、事象が発生する端末に展開します。

2. **ユーザー権限**で PowerSehll を起動し、aad_device_diagnostic-main.zip を展開したフォルダに cd コマンドなどで移動し、dir コマンドなどで aad_log_user.ps1 ファイルが存在することを確認します。

3. 以下を入力し、aad_log_user.ps1 スクリプトを実行します。
```
Powershell.exe -Executionpolicy ByPass .\aad_log_user.ps1
```
4. 現在のユーザーにはローカル管理者権限がある場合、UAC (ユーザーアカウント制御) のウィンドウが表示されますので、[はい] をクリックします。<br />
現在のユーザーにはローカル管理者権限がない場合、UAC のウィンドウでローカル管理者権限の情報を入力し、[はい] をクリックします。


5. 管理者権限で別の PowerShell ウィンドウが起動してきますので、現在のフォルダが aad_device_diagnostic-main.zip を展開したフォルダであることを確認します。<br/>
aad_device_diagnostic-main.zip を展開したフォルダではない場合、aad_device_diagnostic-main.zip を展開したフォルダに PowerShell プロンプト上で移動します。<br/>
**＊手順2 で起動した PowerShell ウィンドウを閉じないて下さい。**


6. 新しい PowerShell ウィンドウで以下のコマンドを実行し、
```
Powershell.exe -Executionpolicy Bypass .\aad_log_admin.ps1
```

7. 以下のメッセージが表示されましたら、スクリプトの実行が止まりますので、事象を再現します。
```
Press Enter key to stop logging.....
```

8. 事象再現後、手順 7 のメッセージが表示されている PowerShell ウィンドウで "Enter" を入力します。

9. 以下のメッセージが表示されましたら、手順 5 で起動した Powershell ウィンドウで "exit" を入力するか、または Powershell ウィンドウの右上の× (バツ) ボタンをクリックし、ウィンドウを閉じます。
```
Now you can close this window by entering 'Exit'.
```
10. ログ採取は引き続き手順 2 で起動した Powershell ウィンドウで継続します。

11. 以下のメッセージが表示されましたら、ログ採取は完了したことを示しますので、C:\AAD_Logs フォルダを .zip などに圧縮し、弊社まで送りください。
```
Thank you for collecging logs.
Please compress [C:\AAD_Logs] folder and send us.
```

