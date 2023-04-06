package org.Pcap;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Main {
    public static void main(String[] args) {
        EthernetListener listener = new EthernetListener();
        listener.setNicName("Realtek PCIe GbE Family Controller");

        SvParser svDecoder = new SvParser();
        KzCalculator calculator = new KzCalculator();

        listener.addListener(packet -> {
            Optional<SvPacket> svPacket = svDecoder.decode(packet);
            if(svPacket.isPresent()){
//                System.out.println("Answer - \n" + svPacket.get().toString(svPacket.get().getDataset()));
                calculator.addPacket(svPacket.get());

                if(calculator.getSvPacketList().size() == 12000){
                    for(int i=0;i<12000;i++){
                        List<Double> normalValues = calculator.findNormal();
                        List<Double> emergencyValue = calculator.findFault(normalValues);
                        List<Double[]> kzTime = calculator.countKz();
                        System.out.println(calculator.getSvPacketList().get(i).toString());
                        System.out.println("Значение токов в нормальном режиме: \n Line A: " + normalValues.get(0) +
                                "\n Line B: " + normalValues.get(1) + "\n Line C: " + normalValues.get(2) +
                                "\n Line N: " + normalValues.get(3));
                        System.out.println("Значение токов в аварийном режиме: \n Line A: " + emergencyValue.get(0) +
                                "\n Line B: " + emergencyValue.get(1) + "\n Line C: " + emergencyValue.get(2) +
                                "\n Line N: " + emergencyValue.get(3));

                    }
                }
            }


        });

        listener.start();


    }
}