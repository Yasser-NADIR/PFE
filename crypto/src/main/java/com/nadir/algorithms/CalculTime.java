package com.nadir.algorithms;

import java.time.Duration;
import java.time.Instant;

import com.google.common.base.Supplier;

public class CalculTime {
    public void CalculTimeProcess(Supplier<?> function) throws Exception {
        Instant start = Instant.now();
        function.get();
        Instant end = Instant.now();
        Duration duree = Duration.between(start, end);
        long min = duree.toMinutes();
        long seconds = duree.getSeconds() - min*60;
        long miliseconds = duree.toMillis() - duree.getSeconds()*1000;
        System.out.println("minutes: "+min+", seconds:"+seconds+", milisecondes: "+miliseconds);
    }

    public void sleep(long ms) throws Exception{
        try{
            Thread.sleep(ms);
        }catch(Exception e){

        }
    }

    public static void main(String[] args) throws Exception {
        new CalculTime().CalculTimeProcess(()->{
            try {
                new CalculTime().sleep(100);
            } catch (Exception e) {
            }
            return new Object();
        });
    }
}
