package org.Pcap;

import lombok.Getter;
import lombok.Setter;

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


    private Dataset dataset = new Dataset();

    @Setter @Getter
    public class Dataset{
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

    }

    public String toString(Dataset dataset){
        String answer = "MAC dist: " + macDst + "\nMac source: " + masSrc +"\nPacket type: "+packetType+"\nApp Id: " +
                Short.toString(appID) + "\nSv Id: "+svId+"\nSample count : "+Integer.toString(smpCount)+"\nConf Ref: "+
                Integer.toString(confRef)+"\nSample Synch: "+Integer.toString(smpSynch) + "\n Inst IA: " +
                Double.toString(dataset.getInstIa())+"\n quality IA: " +
                Integer.toString(dataset.getQIa())+"\n Inst IB: " +
                Double.toString(dataset.getInstIb())+"\n quality IB: " +
                Integer.toString(dataset.getQIb())+"\n Inst IC: " +
                Double.toString(dataset.getInstIc())+"\n quality IC: " +
                Integer.toString(dataset.getQIc())+"\n Inst IN: " +
                Double.toString(dataset.getInstIn())+"\n quality IN: " +
                Integer.toString(dataset.getQIn())+"\n Inst UA: " +
                Double.toString(dataset.getInstUa())+"\n quality UA: " +
                Integer.toString(dataset.getQUa())+"\n Inst UB: " +
                Double.toString(dataset.getInstUb())+"\n quality UB: " +
                Integer.toString(dataset.getQUb())+"\n Inst UC: " +
                Double.toString(dataset.getInstUc())+"\n quality UC: " +
                Integer.toString(dataset.getQUc())+"\n Inst UN: " +
                Double.toString(dataset.getInstUn())+"\n quality UN: " +
                Integer.toString(dataset.getQUn());
        return answer;
    }

}
