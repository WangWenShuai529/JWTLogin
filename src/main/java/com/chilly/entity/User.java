package com.chilly.entity;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * Created by  WWS
 */
@Data
@Accessors(chain = true)
public class User {
    private String id;
    private String name;
    private String password;
}
