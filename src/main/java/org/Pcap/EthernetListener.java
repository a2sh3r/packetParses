package org.Pcap;

import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;


@Slf4j
public class EthernetListener {
    KzCalculator calculator = new KzCalculator();

    static{
        try {
            for (PcapNetworkInterface nic : Pcaps.findAllDevs()) {
                log.info("Found NIC: {}", nic);
            }
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }
    }

    @Setter
    private String nicName;

    private PcapHandle handle;

    private final List<PacketListener> listeners = new CopyOnWriteArrayList<>();
    private final PacketListener defaultPacketListener = packet -> {
        listeners.forEach(listener -> listener.gotPacket(packet));
    };



    @SneakyThrows
    public void start(){
        if (handle == null){
            initializeNetworkInterface();

            if(handle != null){

                String filter = "ether proto 0x88ba && ether dst 01:0C:CD:04:00:01";
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);


                Thread captureThread = new Thread(() -> {
                    try {
                        log.info("Starting packet capture");
                        handle.loop(0, defaultPacketListener);
                    } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                        throw new RuntimeException(e);
                    }

                    log.info("Packet capture finished");
                });

                captureThread.start();
                System.out.println("GAdsadsadsa");
                Thread.sleep(5000);
                captureThread.stop();
                System.out.println("Disabled");
            }
        }

    }

    @SneakyThrows
    private void initializeNetworkInterface() {
         Optional<PcapNetworkInterface> nic = Pcaps.findAllDevs().stream()
                .filter(i -> nicName.equals(i.getDescription()))
                .findFirst();
         if(nic.isPresent()){
            handle = nic.get().openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            log.info("Network handler created: {}", nic);
         }
         else {
            log.error("Network interface not found");
         }
    }


    public void addListener(PacketListener listener){
        listeners.add(listener);
    }


}
