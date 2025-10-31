package com.coraho.ecommerceservice.DTO;


import lombok.*;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDTO {
    private String username;
    private String password;
    private String[] groups;
    private String[] authorities;
}
