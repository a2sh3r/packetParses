package org.Pcap;

import java.util.Optional;

public class Main {
    public static void main(String[] args) {
        EthernetListener listener = new EthernetListener();
        listener.setNicName("Oracle");

        SvParser svDecoder = new SvParser();


        listener.addListener(packet -> {
            Optional<SvPacket> svPacket = svDecoder.decode(packet);
            if(svPacket.isPresent()){
                System.out.println("Answer - \n" + svPacket.get().toString(svPacket.get().getDataset()));

            }

        });
        listener.start();


    }
}