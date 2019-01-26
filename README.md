# ipv6_logging
Скрипт позволяет логировать все IPv6 пакеты, проходящие через указанный сетевой интерфейс.
При прохождении очередного пакета через интерфейс выводится информация об адресе источника и адресе назначения.
## Примеры использования
Для начала рассмотрим вариант с подключением к loopback интерфейсу.  
`sudo python ipv6_logging.py -i lo`  
Для отправки IPv6 пакетов можно воспользоваться утилитой *ping6*.  
`ping6 -c 5 ip6-localhost`  
При этом в окне с запущенным скриптом должны отображаться адреса источника и назначения пакетов.
В данном случае 0:0:0:0:0:0:0:1 для обоих адресов.

Также имеется возможность выполнить запрос на link-local адрес. Для этого необходимо определить IPv6 адрес сетевого интерфейса 
в локальной сети с помощью утилиты *ifconfig*.
Также в запросе должен быть указан сетевой интерфейс. Это может быть сделано при помощи опции `-I` или указанием
сетевого интерфейса после IPv6 адреса через знак `%`  
`ping6 -c 5 fe80::9ef6:ebed:8a27:cb89%wlp3s0`

Для отправки IPv6 пакетов с другого уствройства в локальном сегменте сети необходимо подключиться к сетевому интерфейсу,
через который возможно обращение из локальной сети.
Список сетевых интерфейсов можно узнать при помощи утилиты *ifconfig*  
`sudo python ipv6_logging.py -i wlp3s0`  
Отправка пакетов выполняется так же, как и в варианте с отправкой на link-local адрес.
