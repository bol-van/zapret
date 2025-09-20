Цель этих фильтров - отсекать полезную нагрузку в режиме ядра, не насилуя процессор перенаправлением целого потока на winws.
Задействуются через `winws --wf-raw-part=@filename`. Может быть несколько частичных фильтров. Они могут сочетаться с --wf-tcp и --wf-udp.
Однако, язык фильтров windivert не содержит операций с битовыми полями, сдвигов и побитовой логики.
Поэтому фильтры получились более слабыми, способными передавать неправильную нагрузку.
Дофильтрация производится силами winws.

Описание языка фильтров : https://reqrypt.org/windivert-doc.html#filter_language
Пример инстанса для пробития медиапотоков в discord : `winws --wf-raw-part=@windivert_part.discord_media.txt --wf-raw-part=@windivert_part.stun.txt --filter-l7=stun,discord --dpi-desync=fake`


These filters are invoked using `winws --wf-raw-part=@filename`. Multiple filter parts are supported. They can be combined with --wf-tcp and --wf-udp.
Filters are kernel mode and save great amount of CPU.
However windivert cannot filter by bit fields, lacks shift and bitwise logic operations.
Filters are relaxed and can pass wrong payloads. Finer filtering is done by winws.
