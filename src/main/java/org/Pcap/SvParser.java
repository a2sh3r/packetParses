package org.Pcap;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapPacket;

import java.util.Optional;


@Slf4j
public class SvParser {


    private static final  int datasetSize = 64;

    public Optional<SvPacket> decode(PcapPacket packet) {
        try{
            byte[] data = packet.getRawData();
            int length = data.length;
            SvPacket result = new SvPacket();

            result.setMacDst(byteArrayToMac(data, 0));
            result.setMasSrc(byteArrayToMac(data, 6));

            result.getDataset().setInstIa(byteArrayToInt(data, length - datasetSize) / 100.0);



            return Optional.of(result);
        }
        catch (Exception e){
            log.error("Cannot parse sv packet");
        }



        return Optional.empty();
    }

    public static String byteArrayToMac(byte[] b, int offset){
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x:",
                b[offset],
                b[1+ offset],
                b[2 + offset],
                b[3+ offset],
                b[4+ offset],
                b[5+ offset]
        );
    }

    public static int byteArrayToInt(byte[] b, int offset){
        return b[offset+3] & 0xFF | (b[offset+2] & 0xFF) << 8 | (b[offset+1] & 0xFF) << 16 | (b[offset] & 0xFF) << 24;
    }
}
