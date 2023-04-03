package org.Pcap;

import lombok.Getter;
import lombok.Setter;

@Setter @Getter
public class SvPacket {
    private String macDst;

    private String masSrc;

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

}
