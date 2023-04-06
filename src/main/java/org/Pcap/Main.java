package org.Pcap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Main {
    public static void main(String[] args) {
        EthernetListener listener = new EthernetListener();
        listener.setNicName("Famatech");

        SvParser svDecoder = new SvParser();
        KzCalculator calculator = new KzCalculator();

        listener.addListener(packet -> {
            Optional<SvPacket> svPacket = svDecoder.decode(packet);
            if(svPacket.isPresent()){

//                System.out.println("Answer - \n" + svPacket.get().toString(svPacket.get().getDataset()));
                calculator.addPacket(svPacket.get());

                if(calculator.getSvPacketList().size() == 12000){
                    List<Double> normalValues = calculator.findNormal();
                    List<Double> emergencyValue = calculator.findFault(normalValues);
                    List<String> kzType = new ArrayList<>();
                    List<String> answerTime = new ArrayList<>();
                    List<Double[]> kzTime = calculator.countKz();
                    List<String> answer = new ArrayList<>();


                    var normalMode = "Значение токов в нормальном режиме: Line A:" + normalValues.get(0) +
                            " Line B:" + normalValues.get(1) + " Line C:" + normalValues.get(2) +
                            " Line N:" + normalValues.get(3);

                    var emergencyMode = "Значение токов в аварийном режиме:  Line A:" + emergencyValue.get(0) +
                            " Line B:" + emergencyValue.get(1) + " Line C:" + emergencyValue.get(2) +
                            " Line N:" + emergencyValue.get(3);

                    List<String> modes = new ArrayList<String>();
                    modes.add(normalMode);
                    modes.add(emergencyMode);

                    System.out.println("Значение токов в нормальном режиме: Line A:" + normalValues.get(0) +
                            " Line B:" + normalValues.get(1) + " Line C:" + normalValues.get(2) +
                            " Line N:" + normalValues.get(3));

                    System.out.println("Значение токов в аварийном режиме:  Line A:" + emergencyValue.get(0) +
                            " Line B:" + emergencyValue.get(1) + " Line C:" + emergencyValue.get(2) +
                            " Line N:" + emergencyValue.get(3));

                    try {
                        Files.write(Paths.get("mode-values.txt"), modes, StandardOpenOption.CREATE);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    for(int i=0;i<12000;i++) {

                        var line1 = (i + 1) + "-packet " + calculator.getSvPacketList().get(i).toString(calculator.getSvPacketList().get(i).getDataset());
                        answer.add(line1);
                    }
                    try {
                        Files.write(Paths.get("packets.txt"), answer, StandardOpenOption.CREATE);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    for(int i=0;i<12000;i++) {
                        var item = calculator.getKzType().get(i);
                        if(calculator.getKzType().get(i) == "") {
                            String line = i+1 + " -  net Kz";

                            kzType.add(line);
                        }
                        else {
                            String line = i+1 + " - " + calculator.getKzType().get(i);
                            kzType.add(line);
                        }

                    }

                    try {
                        Files.write(Paths.get("kz-types.txt"), kzType, StandardOpenOption.CREATE);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                }
            }


        });

        listener.start();


    }
}