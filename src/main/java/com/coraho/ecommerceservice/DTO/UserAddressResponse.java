package com.coraho.ecommerceservice.DTO;

import com.coraho.ecommerceservice.entity.UserAddress.AddressType;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserAddressResponse {
    private Long id;
    private AddressType addressType;
    private Boolean isDefault;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String addressLine1;
    private String addressLine2;
    private String city;
    private String stateProvince;
    private String postalCode;
    private String country;
}
