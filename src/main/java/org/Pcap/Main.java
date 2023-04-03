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
                System.out.println("instIa - " + svPacket.get().getDataset().getInstIa());
                System.out.println("instIb - " + svPacket.get().getDataset().getInstIb());
                System.out.println("instIc - " + svPacket.get().getDataset().getInstIc());
                System.out.println("instIn - " + svPacket.get().getDataset().getInstIn());
                System.out.println("qIa - " + svPacket.get().getDataset().getQIa());
                System.out.println("qIb - " + svPacket.get().getDataset().getQIb());
                System.out.println("qIc - " + svPacket.get().getDataset().getQIc());
                System.out.println("qIn - " + svPacket.get().getDataset().getQIn());
                System.out.println("instUa - " + svPacket.get().getDataset().getInstUa());
                System.out.println("instUb - " + svPacket.get().getDataset().getInstUb());
                System.out.println("instUc - " + svPacket.get().getDataset().getInstUc());
                System.out.println("instUn - " + svPacket.get().getDataset().getInstUn());
                System.out.println("qUa - " + svPacket.get().getDataset().getQUa());
                System.out.println("qUb - " + svPacket.get().getDataset().getQUb());
                System.out.println("qUc - " + svPacket.get().getDataset().getQUc());
                System.out.println("qUn - " + svPacket.get().getDataset().getQUn());
            }

        });
        listener.start();


    }
}