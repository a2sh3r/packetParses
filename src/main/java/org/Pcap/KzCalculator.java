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
    private List<String> kzType = new ArrayList<>();


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

            var sumuA = 0.0;
            var sumuB = 0.0;
            var sumuC = 0.0;
            var sumuN = 0.0;

            for (int i = 0; i < 200; i++) {
                sumA = sumA + Math.abs(svPacketList.get(i).getDataset().getInstIa()) * Math.abs(svPacketList.get(i).getDataset().getInstIa());
                sumB = sumB + Math.abs(svPacketList.get(i).getDataset().getInstIb()) * Math.abs(svPacketList.get(i).getDataset().getInstIb());
                sumC = sumC + Math.abs(svPacketList.get(i).getDataset().getInstIc()) * Math.abs(svPacketList.get(i).getDataset().getInstIc());
                sumN = sumN + Math.abs(svPacketList.get(i).getDataset().getInstIn()) * Math.abs(svPacketList.get(i).getDataset().getInstIn());

                sumuA = sumuA + Math.abs(svPacketList.get(i).getDataset().getInstUa()) * Math.abs(svPacketList.get(i).getDataset().getInstUa());
                sumuB = sumuB + Math.abs(svPacketList.get(i).getDataset().getInstUb()) * Math.abs(svPacketList.get(i).getDataset().getInstUb());
                sumuC = sumuC + Math.abs(svPacketList.get(i).getDataset().getInstUc()) * Math.abs(svPacketList.get(i).getDataset().getInstUc());
                sumuN = sumuN + Math.abs(svPacketList.get(i).getDataset().getInstUn()) * Math.abs(svPacketList.get(i).getDataset().getInstUn());

            }

            double ustA = Math.sqrt(sumA / 200) * 2.2;
            double ustB = Math.sqrt(sumB / 200) * 2.2;
            double ustC = Math.sqrt(sumC / 200) * 2.2;
            double ustN = Math.sqrt(sumN / 200) * 2.2;

            double ustuA = Math.sqrt(sumuA / 200) * 2.2;
            double ustuB = Math.sqrt(sumuB / 200) * 2.2;
            double ustuC = Math.sqrt(sumuC / 200) * 2.2;
            double ustuN = Math.sqrt(sumuN / 200) * 2.2;

            currentsNormal.add(ustA);
            currentsNormal.add(ustB);
            currentsNormal.add(ustC);
            currentsNormal.add(ustN);

            currentsNormal.add(ustuA);
            currentsNormal.add(ustuB);
            currentsNormal.add(ustuC);
            currentsNormal.add(ustuN);
        }

        return currentsNormal;
    }

    public List<Double> findFault(List<Double> currentsNormal) {
        List<Double> currentsEmergency = new ArrayList<>();

        var emergencyIa = 0.0;
        var emergencyIb = 0.0 ;
        var emergencyIc = 0.0;
        var emergencyIn = 0.0;

        var emergencyUa = 0.0;
        var emergencyUb = 0.0 ;
        var emergencyUc = 0.0;
        var emergencyUn = 0.0;

        var countera = 1;
        var counterb = 1;
        var counterc = 1;
        var countern = 1;




        for (int i = 0; i < svPacketList.size(); i++) {
            String kzName ="";
            var item = svPacketList.get(i).getDataset();
            kzName = "";

            if(Math.abs(item.getInstIa()) > currentsNormal.get(0))
            {
                emergencyIa += Math.abs(item.getInstIa());
                emergencyUa += Math.abs(item.getInstUa());
                countera += 1;
                kzName += "A";
            }
            if(Math.abs(item.getInstIb()) > currentsNormal.get(1))
            {
                emergencyIb += Math.abs(item.getInstIb());
                emergencyUb += Math.abs(item.getInstUb());
                counterb += 1;
                kzName += "B";
            }
            if(Math.abs(item.getInstIc()) > currentsNormal.get(2))
            {
                emergencyIc += Math.abs(item.getInstIc());
                emergencyUc += Math.abs(item.getInstUc());
                counterc += 1;
                kzName += "C";
            }
            if(Math.abs(item.getInstIn()) > currentsNormal.get(3))
            {
                emergencyIn += Math.abs(item.getInstIn());
                emergencyUn += Math.abs(item.getInstUn());
                countern += 1;
                kzName += "N";
            }
            kzType.add(kzName);

        }

        currentsEmergency.add(emergencyIa/countera);
        currentsEmergency.add(emergencyIb/counterb);
        currentsEmergency.add(emergencyIc/counterc);
        currentsEmergency.add(emergencyIn/countern);

        currentsEmergency.add(emergencyUa/countera);
        currentsEmergency.add(emergencyUb/counterb);
        currentsEmergency.add(emergencyUc/counterc);
        currentsEmergency.add(emergencyUn/countern);

        return currentsEmergency;
    }

    public List<Double[]> countKz(){
        double startCounter = 0;
        double endCounter = 0;
        List<Double[]> emergencyTime = new ArrayList<>();



        for (int i = 1; i < svPacketList.size(); i++) {
            if((svPacketList.get(i).getKz() != "") & (svPacketList.get(i-1).getKz() == "")){
                startCounter = i;
            }
            if (((svPacketList.get(i).getKz() == "") & (svPacketList.get(i-1).getKz() != ""))){
                endCounter = i;
            }
            if (startCounter >0 & endCounter >0){
                emergencyTime.add(new Double[] {startCounter, endCounter});
            }

        }

        for (int i = 0; i < emergencyTime.size(); i++) {
            double time = (emergencyTime.get(i)[1] - emergencyTime.get(i)[0]) * 0.00025;
            emergencyTime.set(i, new Double[] {time, emergencyTime.get(i)[0], emergencyTime.get(i)[1]});

        }

        return emergencyTime;
    }

    private double getValue(int i){
        return svPacketList.get(i).getDataset().getInstIa();


    }

    public List<SvPacket> getSvPacketList() {
        return svPacketList;
    }


}
