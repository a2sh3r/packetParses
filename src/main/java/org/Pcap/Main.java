package org.Pcap;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Main {
    public static void main(String[] args) {
        EthernetListener listener = new EthernetListener();
        listener.setNicName("Oracle");

        SvParser svDecoder = new SvParser();
        KzCalculator calculator = new KzCalculator();

        listener.addListener(packet -> {
            Optional<SvPacket> svPacket = svDecoder.decode(packet);
            if(svPacket.isPresent()){
//                System.out.println("Answer - \n" + svPacket.get().toString(svPacket.get().getDataset()));
                calculator.addPacket(svPacket.get());
                System.out.println(calculator.findNormal());

            }


        });

        listener.start();

//
//        boolean flag = true;
//        while (flag == true) {
//            System.out.println(calculator.getSvPacketList().size());
//        }

        List<Integer> falseIa = new ArrayList<>();
        List<Integer> falseIb = new ArrayList<>();
        List<Integer> falseIc = new ArrayList<>();
        List<Integer> falseIn = new ArrayList<>();

//        while (flag == true) {
//            if(calculator.getSvPacketList().size()>0) {
//                for (int i = 0; i < calculator.getSvPacketList().size(); i++) {
//                    System.out.println(calculator.getSvPacketList().get(i).getDataset().getInstIa());
//                }
//            }
//            if((calculator.getSvPacketList().size() % 12000 == 0) & (calculator.getSvPacketList().size() > 0)){
//                for(int i=0; i<calculator.getSvPacketList().size();i++) {
//                    calculator.getSvPacketList().get(i).getDataset().setUstCurrent(calculator.findNormal());
//                }
//                for(int i=0; i<calculator.getSvPacketList().size();i++) {
//                    if(Math.abs(calculator.getSvPacketList().get(i).getDataset().getInstIa()) >
//                            calculator.getSvPacketList().get(i).getDataset().getUstCurrent().get(0)){
//                        falseIa.add(i);
//                    }
//                    if(Math.abs(calculator.getSvPacketList().get(i).getDataset().getInstIb()) >
//                            calculator.getSvPacketList().get(i).getDataset().getUstCurrent().get(1)){
//                        falseIb.add(i);
//                    }
//                    if(Math.abs(calculator.getSvPacketList().get(i).getDataset().getInstIc()) >
//                            calculator.getSvPacketList().get(i).getDataset().getUstCurrent().get(2)){
//                        falseIc.add(i);
//                    }
//                    if(Math.abs(calculator.getSvPacketList().get(i).getDataset().getInstIn()) >
//                            calculator.getSvPacketList().get(i).getDataset().getUstCurrent().get(3)){
//                        falseIn.add(i);
//                    }
//                }
//
//            }
//            if(falseIa.size()>0) {
//                System.out.println("false Ia - " + falseIa.get(0));
//            }
//            if(falseIa.size()>0) {
//                System.out.println("false Ib - " + falseIb.get(0));
//            }
//            if(falseIa.size()>0) {
//                System.out.println("false Ic - " + falseIc.get(0));
//            }
//            if(falseIa.size()>0) {
//                System.out.println("false In - " + falseIn.get(0));
//            }
//        }




    }
}