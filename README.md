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
В данном датасете 14261 пакетов и 1209 потоков. Оптимальной нагрузкой работы было 4 Mbps.
```
Flows: 1212, Packets: 45420, Bytes: 8216531, Sequence Errors: 0, Bad Packets: 0
Total ignored packets: 0
Flows: 2, Packets: 2012, Bytes: 122112, Sequence Errors: 0, Bad Packets: 0
Total ignored packets: 0
```

Для датасета bigFlows (791615 пакетов и 40686 потоков). При скорости ~5.5 Mbps.
```
Flows: 22002, Packets: 217587, Bytes: 89201433, Sequence Errors: 165, Bad Packets: 0
Total ignored packets: 0
Flows: 17788, Packets: 552923, Bytes: 198130198, Sequence Errors: 297, Bad Packets: 0
Total ignored packets: 0
```
Суммарно потеряно ~2.3% пакетов и ~2.3% потоков.
