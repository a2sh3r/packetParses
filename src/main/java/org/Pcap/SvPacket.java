package org.Pcap;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter @Getter
public class SvPacket {
    private String macDst;

    private String masSrc;
    private String packetType;

    private short appID;

    private String svId;

    private int smpCount;

    private int confRef;

    private int smpSynch;

    private String kz;


    private Dataset dataset = new Dataset();

    @Setter @Getter
    public static class Dataset{
        private double instIa;
        private int qIa;
        private double instIb;
        private int qIb;
        private double instIc;
        private int qIc;
        private double instIn;
        private int qIn;


        private double instUa;
        private int qUa;
        private double instUb;
        private int qUb;
        private double instUc;
        private int qUc;
        private double instUn;
        private int qUn;

        private List<Double> ustCurrent;

    }

    public String toString(Dataset dataset){
        return "MAC-dist:" + macDst + " Mac-source:" + masSrc +" Packet-type:"+packetType+" App-Id:" +
                Short.toString(appID) + " Sv-Id:"+svId+" Sample-count:"+Integer.toString(smpCount)+" Conf-Ref:"+
                Integer.toString(confRef)+" Sample-Synch:"+Integer.toString(smpSynch) + " Inst-IA:" +
                Double.toString(dataset.getInstIa())+" quality-IA:" +
                Integer.toString(dataset.getQIa())+" Inst-IB:" +
                Double.toString(dataset.getInstIb())+" quality-IB:" +
                Integer.toString(dataset.getQIb())+" Inst-IC:" +
                Double.toString(dataset.getInstIc())+" quality-IC:" +
                Integer.toString(dataset.getQIc())+" Inst-IN:" +
                Double.toString(dataset.getInstIn())+" quality-IN:" +
                Integer.toString(dataset.getQIn())+" Inst UA: " +
                Double.toString(dataset.getInstUa())+" quality-UA:" +
                Integer.toString(dataset.getQUa())+" Inst UB: " +
                Double.toString(dataset.getInstUb())+" quality-UB:" +
                Integer.toString(dataset.getQUb())+" Inst-UC:" +
                Double.toString(dataset.getInstUc())+" quality-UC:" +
                Integer.toString(dataset.getQUc())+" Inst-UN:"+
                Double.toString(dataset.getInstUn())+" quality-UN:" +
                Integer.toString(dataset.getQUn());
    }

}
