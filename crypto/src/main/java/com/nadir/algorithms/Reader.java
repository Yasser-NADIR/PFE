package com.nadir.algorithms;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Reader {
    String write = "C:\\Users\\YasserNADIR\\Documents\\PFE\\crypto\\files\\";
    int OneMoTaile = 1024*1024;
    public void readFile(String filename, int Mo) throws Exception{
        File file = new File(filename);
        FileInputStream in = new FileInputStream(file);
        byte[] readedBuffer = new byte[OneMoTaile*Mo];
        in.read(readedBuffer);
        in.close();
    }


    public void createFilesForTest() throws Exception{
        List<String> names = Stream.of("OneMo", "TwoMo", "FiveMo", "TenMo", "TwentyMO").collect(Collectors.toList());
        File file;
        FileOutputStream out;
        int taille=1;
        for(String name : names){
            file = new File(write+name+".txt");
            out = new FileOutputStream(file);
            for(int i=0; i<OneMoTaile*taille; i++){
                out.write('a');
            }
            switch(taille){
                case 1:
                taille = 2;
                break;
                case 2:
                taille = 5;
                break;
                case 5:
                taille = 10;
                break;
                case 10:
                taille = 20;
                break;
            }
            out.close();
        }
    }

    public static void main(String[] args)throws Exception {
        Reader reader = new Reader();
        CalculTime calcul = new CalculTime();
        calcul.CalculTimeProcess(()->{
            try {
                reader.createFilesForTest();
            } catch (Exception e) {
            }
            return new Object();
        });
    }
}
