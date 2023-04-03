package org.Pcap;

import java.util.Optional;

public class Main {
    public static void main(String[] args) {
        EthernetListener listener = new EthernetListener();
        listener.setNicName("Microsoft Wi-Fi Direct Virtual Adapter");

        SvParser svDecoder = new SvParser();


        listener.addListener(packet -> {
            Optional<SvPacket> svPacket = svDecoder.decode(packet);
            if(svPacket.isPresent()){
                System.out.println(svPacket);
            }
            System.out.println(packet);

        });
        listener.start();


    }
}