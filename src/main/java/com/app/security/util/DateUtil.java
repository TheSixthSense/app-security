package com.app.security.util;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class DateUtil {

    /**
     * Date -> LocalDateTime
    */
    public static LocalDateTime changeLocalDateTime(Date date) {
        return LocalDateTime.ofInstant(date.toInstant(), ZoneId.of("Asia/Seoul"));
    }
}
