# aad_device_diagnostic

1. [ここ](https://github.com/jpazureid/aad_device_diagnostic/archive/refs/heads/main.zip) から aad_device_diagnostic-main.zip をダウンロードし、事象が発生する端末に展開します。

2. **ユーザー権限**で PowerShell を起動し、aad_device_diagnostic-main.zip を展開したフォルダに cd コマンドなどで移動し、dir コマンドなどで aad_log_user.ps1 ファイルが存在することを確認します。

3. 以下を入力し、aad_log_user.ps1 スクリプトを実行します。
```
Powershell.exe -Executionpolicy ByPass .\aad_log_user.ps1
```
4. 現在のユーザーにはローカル管理者権限がある場合、UAC (ユーザーアカウント制御) のウィンドウが表示されますので、[はい] をクリックします。<br/>
現在のユーザーにはローカル管理者権限がない場合、UAC のウィンドウでローカル管理者権限の情報を入力し、[はい] をクリックします。

5. 管理者権限で別の PowerShell ウィンドウが起動しログ採取の事前処理が実施されます。 以下のメッセージが表示されましたら、スクリプトの実行が止まりますので、事象を再現します。

```
Press Enter key to stop logging.....
```
**＊手順2 で起動した PowerShell ウィンドウを閉じないて下さい。**

6. 事象再現後、手順 5 のメッセージが表示されている PowerShell ウィンドウで "Enter" を入力します。
**"Enter" を入力した後、以下のメッセージが表示されることがあります。そのまま "R" を入力してください。**

```
この信頼されていない発行元からのソフトウェアを実行しますか?
```

7. ログの採取が完了すると、管理者権限で起動した PowerShell が自動で閉じられます。

8. ログ採取は引き続き手順 2 で起動した Powershell ウィンドウで継続します。

9. 以下のメッセージが表示されましたら、ログ採取は完了したことを示しますので、C:\AAD_Logs フォルダを .zip などに圧縮し、弊社まで送りください。
```
Thank you for collecting logs.
Please compress [C:\AAD_Logs] folder and send us.
```

