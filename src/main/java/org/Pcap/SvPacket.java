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
        return "MAC dist: " + macDst + "\nMac source: " + masSrc +"\nPacket type: "+packetType+"\nApp Id: " +
                Short.toString(appID) + "\nSv Id: "+svId+"\nSample count : "+Integer.toString(smpCount)+"\nConf Ref: "+
                Integer.toString(confRef)+"\nSample Synch: "+Integer.toString(smpSynch) + "\nInst IA: " +
                Double.toString(dataset.getInstIa())+"\nquality IA: " +
                Integer.toString(dataset.getQIa())+"\nInst IB: " +
                Double.toString(dataset.getInstIb())+"\nquality IB: " +
                Integer.toString(dataset.getQIb())+"\nInst IC: " +
                Double.toString(dataset.getInstIc())+"\nquality IC: " +
                Integer.toString(dataset.getQIc())+"\nInst IN: " +
                Double.toString(dataset.getInstIn())+"\nquality IN: " +
                Integer.toString(dataset.getQIn())+"\nInst UA: " +
                Double.toString(dataset.getInstUa())+"\nquality UA: " +
                Integer.toString(dataset.getQUa())+"\nInst UB: " +
                Double.toString(dataset.getInstUb())+"\nquality UB: " +
                Integer.toString(dataset.getQUb())+"\nInst UC: " +
                Double.toString(dataset.getInstUc())+"\nquality UC: " +
                Integer.toString(dataset.getQUc())+"\nInst UN: " +
                Double.toString(dataset.getInstUn())+"\nquality UN: " +
                Integer.toString(dataset.getQUn());
    }

}
