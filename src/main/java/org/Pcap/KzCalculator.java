package org.Pcap;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;

@Setter @Getter
public class KzCalculator {

    private List<SvPacket> svPacketList = new ArrayList<SvPacket>();
    private Double setPoint;
    public void addPacket(SvPacket packet){
        svPacketList.add(packet);
    }

    public List<Double> findNormal(){
        List<Double> currentsNormal = new ArrayList<>();
        if (svPacketList.size()>200) {

            var sumA = 0.0;
            var sumB = 0.0;
            var sumC = 0.0;
            var sumN = 0.0;

            for (int i = 0; i < 200; i++) {
                sumA = sumA + Math.abs(svPacketList.get(i).getDataset().getInstIa()) * Math.abs(svPacketList.get(i).getDataset().getInstIa());
                sumB = sumB + Math.abs(svPacketList.get(i).getDataset().getInstIb()) * Math.abs(svPacketList.get(i).getDataset().getInstIb());
                sumC = sumC + Math.abs(svPacketList.get(i).getDataset().getInstIc()) * Math.abs(svPacketList.get(i).getDataset().getInstIc());
                sumN = sumN + Math.abs(svPacketList.get(i).getDataset().getInstIn()) * Math.abs(svPacketList.get(i).getDataset().getInstIn());

            }

            double ustA = Math.sqrt(sumA / 200) * 2;
            double ustB = Math.sqrt(sumB / 200) * 2;
            double ustC = Math.sqrt(sumC / 200) * 2;
            double ustN = Math.sqrt(sumN / 200) * 2;

            currentsNormal.add(ustA);
            currentsNormal.add(ustB);
            currentsNormal.add(ustC);
            currentsNormal.add(ustN);
        }

        return currentsNormal;
    }

    private double getValue(int i){
        return svPacketList.get(i).getDataset().getInstIa();
    }

    public List<SvPacket> getSvPacketList() {
        return svPacketList;
    }
}
