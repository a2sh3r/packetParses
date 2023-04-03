package org.Pcap;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapPacket;

import java.nio.charset.StandardCharsets;
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
            result.setPacketType(byteArrayToType(data, 12));
            result.setAppID(byteArrayToShort(data, 14));
            result.setSvId(byteArrayToSvId(data, 33));
            result.setSmpCount(byteArrayToInt32(data, 45));
            result.setConfRef(byteArrayToInt(data, 49));
            result.setSmpSynch(byteArrayToIntShort(data, 55));

            result.getDataset().setInstIa(byteArrayToInt(data, length - datasetSize) / (100.0*1000.0));
            result.getDataset().setInstIb(byteArrayToInt(data, length - datasetSize + 8) / (100.0*1000.0));
            result.getDataset().setInstIc(byteArrayToInt(data, length - datasetSize + 16) / (100.0*1000.0));
            result.getDataset().setInstIn(byteArrayToInt(data, length - datasetSize + 24) / (100.0*1000.0));

            result.getDataset().setQIa(byteArrayToInt(data, length - datasetSize + 4));
            result.getDataset().setQIb(byteArrayToInt(data, length - datasetSize + 12));
            result.getDataset().setQIc(byteArrayToInt(data, length - datasetSize + 20));
            result.getDataset().setQIn(byteArrayToInt(data, length - datasetSize + 28));

            result.getDataset().setInstUa(byteArrayToInt(data, length - datasetSize + 32) / (100.0*1000.0));
            result.getDataset().setInstUb(byteArrayToInt(data, length - datasetSize + 40) / (100.0*1000.0));
            result.getDataset().setInstUc(byteArrayToInt(data, length - datasetSize + 48) / (100.0*1000.0));
            result.getDataset().setInstUn(byteArrayToInt(data, length - datasetSize + 56) / (100.0*1000.0));

            result.getDataset().setQUa(byteArrayToInt(data, length - datasetSize + 36));
            result.getDataset().setQUb(byteArrayToInt(data, length - datasetSize + 44));
            result.getDataset().setQUc(byteArrayToInt(data, length - datasetSize + 52));
            result.getDataset().setQUn(byteArrayToInt(data, length - datasetSize + 60));

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

    public static String byteArrayToSvId(byte[] b, int offset){
        byte[] by = {b[offset], b[offset+1], b[offset+2], b[offset+3], b[offset+4], b[offset+5], b[offset+6],
                b[offset+7], b[offset+8], b[offset+9]};
        return new String(by, StandardCharsets.US_ASCII);
    }

    public static String byteArrayToType(byte[] b, int offset){
        return String.format("0x%02x,%02x",
                b[offset],
                b[1+ offset]
        );
    }

    public static short byteArrayToShort(byte[] b, int offset){
        return (short) (b[offset+1] & 0xFF | (b[offset]) << 8);
    }

    public static int byteArrayToInt(byte[] b, int offset){
        return b[offset+3] & 0xFF | (b[offset+2] & 0xFF) << 8 | (b[offset+1] & 0xFF) << 16 | (b[offset] & 0xFF) << 24;
    }

    public static int byteArrayToInt32(byte[] b, int offset){
        return (b[offset+1] & 0xFF) | (b[offset] & 0xFF) << 8;
    }

    public static int byteArrayToIntShort(byte[] b, int offset){
        return (b[offset] & 0xFF);
    }
}
