package io.abetobing.snap;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class SandboxRun {
    public static void main(String[] args) {
        Instant instant = Instant.now() ;
        ZoneId z = ZoneId.systemDefault();
        DateTimeFormatter format = DateTimeFormatter.ofPattern("yyyy-mm-dd'T'hh:mm:ss.SSSO");
        System.out.println(instant.atZone( z ).format(format));
    }
}
