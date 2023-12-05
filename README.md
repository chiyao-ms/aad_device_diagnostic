# Entra ID Device Diagnostic

## 簡易版採取手順
1. 本サイトの Code をクリックし、Download ZIP から　aad_device_diagnostic-main.zip をダウンロードし、事象が発生する端末に展開します。

2. **事象が発生するユーザー、または通常端末を利用するユーザーの権限**で PowerShell を起動し、aad_device_diagnostic-main.zip を展開したフォルダに cd コマンド等で移動します。
3. 以下のコマンドを入力し、aad_log_user.ps1 スクリプトを実行します。

```
Powershell.exe -Executionpolicy ByPass .\aad_log_user.ps1
```

4. 以下のメッセージが表示されます。<ユーザー名> は通常端末を利用するユーザーであることを確認します。
確認できましたら、最後のメッセージにて "Y" と入力します。

```
Start collecting logs under user <ユーザー名> (<ユーザー名>) context.

Are you sure you want to proceed (Y:Yes/N:No): Y
```

5. 以下のメッセージが表示されましたら、ログの採取が完了しますので、C:\AAD_Logs フォルダを .zip などに圧縮し、弊社まで送りください。

```
Thank you for collecting logs.
Please compress [C:\AAD_Logs] folder and send it to us.
```


## 詳細版採取手順
1. 本サイトの Code をクリックし、Download ZIP から　aad_device_diagnostic-main.zip をダウンロードし、事象が発生する端末に展開します。

2. **管理者権限**で PowerSehll を起動し、aad_device_diagnostic-main.zip を展開したフォルダに cd コマンド等で移動します。

3. 以下を入力し、aad_log_admin.ps1 スクリプトを実行します。

```
Powershell.exe -Executionpolicy Bypass .\aad_log_admin.ps1
```

4. 以下のメッセージが表示されます。<ユーザー名> はログ採取に利用するユーザーであり、管理者権限を持つユーザーであることを確認します。
確認できましたら、最後のメッセージにて "Y" と入力します。

```
Start collecting logs under user <ユーザー名> (<ユーザー名>) context.
Please make sure this user <ユーザー名> (<ユーザー名>) has administrator priviledge.

Are you sure you want to proceed (Y:Yes/N:No): Y
```

5. 以下のメッセージが表示されましたら、スクリプトの実行が止まりますので起動している PowerShell ウィンドウを閉じずに次の手順に進みます。

```
Press Enter key to stop logging.....
```

6. 事象を再現します。

7. 事象再現後、手順 5 のメッセージが表示されている PowerShell ウィンドウで "Enter" キーを入力します。

8. 以下のメッセージが表示されましたら、管理者権限でのログ採取は完了しますので次に進みます。

```
Collecting log by administrator context is done.
```

9. **事象が発生するユーザー、または通常端末を利用するユーザーの権限**で PowerShell を起動し (「管理者として実行」は利用しないでください)、aad_device_diagnostic-main.zip を展開したフォルダに cd コマンド等で移動します。
10. 以下のコマンドを入力し、aad_log_user.ps1 スクリプトを実行します。

```
Powershell.exe -Executionpolicy ByPass .\aad_log_user.ps1
```

11. 以下のメッセージが表示されます。<ユーザー名> は通常端末を利用するユーザーであることを確認します。
確認できましたら、最後のメッセージにて "Y" と入力します。

```
Start collecting logs under user <ユーザー名> (<ユーザー名>) context.

Are you sure you want to proceed (Y:Yes/N:No): Y
```

12. 以下のメッセージが表示されましたら、ログの採取が完了しますので、C:\AAD_Logs フォルダを .zip などに圧縮し、弊社まで送りください。

```
Thank you for collecting logs.
Please compress [C:\AAD_Logs] folder and send it to us.
```
