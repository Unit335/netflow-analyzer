# Netflow Exporter
## Описание

Утилита выполняет сбор статистики по входящим пакетам, объединяя их в потоки и отправляя данные о потоке через фиксированные периоды времени или по истечению срока жизни потока. 
Отправка шаблонов наборов данных происходит при первом запуске и далее регулярно согласно параметру FLOWSET_EXPORT, определнному в main.h.
Для адресации данных потоков используется зэш-таблица на основе сторонней библиотеки uthash (https://troydhanson.github.io/uthash/).

## Сборка

Сборка исполняемого файла netflow-analyzer
```sh
~$ git clone https://github.com/Unit335/netflow-analyzer
~$ cd 
~$ make
```

Сборка deb пакета
```sh
~$ make deb
```

## Запуск

В утилите используется следующий синтакси опций запуска, для работы необходимо указать сетевой интерфейс для работы и адрес + порт коллектора.
```
netflow-analyzer [ --interface INTERFACE-dest DESTINATION_IP --dest_port DESTINATION_PORT ]
interface: название сетевого интерфейса на котором необходимо отслеживать пакеты
dest: IP адрес коллектора в формате XXX.XXX.XXX.XXX 
dest_port: порт коллектора
```
Остальные параметры работы определены в main.h. 

Например:
```sh
~$ sudo netflow-analyzer --interface enp0s3 --dest 127.0.0.1 --dest_port 9995 
Starting
```


## Пропускная способность

Пропускная способность тестировалась с помощью tcpreplay и nfcapd в качестве коллектора из пакета nfdump. Для тестового набора пакетов был взят smallFlows https://tcpreplay.appneta.com/wiki/captures.html#smallflows-pcap
В данном датасете 14261 пакетов и 1209 потоков.

Тест на скорости 500 Mbps с 30ю повторениями набора.

TCPReplay:
```
$ sudo tcpreplay -i lo -l 30 -M 500  smallFlows.pcap 
Warning in sendpacket.c:sendpacket_open_pf() line 942:
Unsupported physical layer type 0x0304 on lo.  Maybe it works, maybe it won't.  See tickets #123/318
Actual: 427830 packets (276495930 bytes) sent in 4.42 seconds
Rated: 62496621.9 Bps, 499.97 Mbps, 96702.79 pps
Flows: 1209 flows, 273.27 fps, 12818700 flow packets, 16200 non-flow
Statistics for network device: lo
	Successful packets:        427830
	Failed packets:            0
	Truncated packets:         0
	Retried packets (ENOBUFS): 0
	Retried packets (EAGAIN):  0
```

Вывод nfcapd:
```
Process_v9: New exporter: SysID: 1, Domain: 1, IP: 127.0.0.1
Process_v9: [1] Add template 256
Ident: 'none' Flows: 1209, Packets: 425492, Bytes: 275001075, Sequence Errors: 0, Bad Packets: 0
Total ignored packets: 0
Ident: 'none' Flows: 1, Packets: 1209, Bytes: 161872, Sequence Errors: 0, Bad Packets: 0
Total ignored packets: 0
```

Потеряно 0.546% пакетов.
При дальнейшем тестировании (с аналогичным повторением набора данных 30 раз) на скорости 80 Mbps удалось достичь отсутствия потерь, с ~100 Mbps они составляли ~0.46%, на 650 уже ~0.9%.
На максимальной скорости - 2031.98 Mbps - потеря пакетов составила ~17%.
