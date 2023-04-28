# goarpreplay

## usage

```
goarpreplay -i eth0 -a 192.168.0.1 -m 00:11:22:33:44:55
```

指定したインターフェイスに対して、指定したIPアドレスのARP Requestを受けた場合に、  
指定したMACアドレスでARP Replyを返す。

MACアドレスを指定しない場合は、指定したインターフェイスのMACアドレスを使用する。