# packetParses
## Домашка для вайршарка

# Реализация
Программа реализована без использования потоков кроме листнера. В мейне в листнере стоит ограничение в 12000 пакетов, при достижении которого начинается анализ  токов короткого замыкания по трем линиям.
Ввиду этого ограничения программа работает только для одной пачки пакетов. Для загрузки последующих программу неободимо перезагружать.

# Вывод ответа
Ответы программы выводятся в 4 отдельных текстовых файла:
+ packets: список всех пришедших пакетов со всеми параметрами
+ Mode-values: токи в нормальном и аварийном режиме
+ kz-types: для каждого пакеты выведен вид короткого замыкания
+ emergency-time: для каждого случившегося аварийного режима (разные типы кз разделены) записаны времядействия, начальный и конечный индексы

###### Код, ввиду того, что ранее не работал с потоками и спешкой за дедлайном, написан очень криво, за что извиняюсь.


# ඞඞඞ
