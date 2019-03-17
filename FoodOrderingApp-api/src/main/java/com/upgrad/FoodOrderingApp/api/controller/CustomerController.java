package com.upgrad.FoodOrderingApp.api.controller;


import com.fasterxml.jackson.databind.introspect.TypeResolutionContext;
import com.upgrad.FoodOrderingApp.api.model.LoginResponse;
import com.upgrad.FoodOrderingApp.api.model.SignupCustomerRequest;
import com.upgrad.FoodOrderingApp.api.model.SignupCustomerResponse;
import com.upgrad.FoodOrderingApp.service.businness.CustomerService;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.UUID;


/**
 * This class exposes rest apis for customer related operations.
 */
@RestController
@CrossOrigin
@RequestMapping("/")
public class CustomerController {

    public static final String CUSTOMER_SUCCESSFULLY_REGISTERED = "CUSTOMER SUCCESSFULLY REGISTERED";
    private static final String SIGNIN_MESSAGE = "SIGNED IN SUCCESSFULLY";


    @Autowired
    private CustomerService customerService;


    /**
     * Rest Endpoint method implementation used for signing up customer with all details.
     *
     * @param signupUserRequest request object containing user details.
     * @return ResponseEntity containing user response
     * @throws SignUpRestrictedException exception thrown in case username of email id are same.
     */
    @RequestMapping(method = RequestMethod.POST, path = "/customer/signup", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<SignupCustomerRequest> signUp(final SignupCustomerRequest signupUserRequest) throws SignUpRestrictedException {
        //Set the customer entity object
        CustomerEntity customerEntity = new CustomerEntity();
        customerEntity.setUuid(UUID.randomUUID().toString());
        customerEntity.setFirstName(signupUserRequest.getFirstName());
        customerEntity.setLastName(signupUserRequest.getLastName());
        customerEntity.setEmail(signupUserRequest.getEmailAddress());
        customerEntity.setContactNumber(signupUserRequest.getContactNumber());
        customerEntity.setPassword(signupUserRequest.getPassword());
        //Pass the customer entity object for persisting in database.
        CustomerEntity createdCustomerEntity = customerService.saveCustomer(customerEntity);
        SignupCustomerResponse customerResponse = new SignupCustomerResponse().id(createdCustomerEntity.getUuid()).status(CUSTOMER_SUCCESSFULLY_REGISTERED);
        return new ResponseEntity(customerResponse, HttpStatus.CREATED);

    }


    /**
     * Rest Endpoint method implementation  used to signin a user into the system.
     * The user is first authenticated with his username and password.
     * Then, user auth token is created and with this auth token user
     * is given access to the application.
     *
     * @param authorization authorization string provided in the format "Basic <BASE64 encoded value>"
     * @return ResponseEntity providing signinresponse object
     * @throws AuthenticationFailedException if user is not authenticated then this exception is thrown
     */

    @RequestMapping(method = RequestMethod.POST, path = "customer/login", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<LoginResponse> signin(@RequestHeader final String authorization) throws AuthenticationFailedException {
        //TypeResolutionContext.Basic dXNlcm5hbWU6cGFzc3dvcmQ =
        //above is a sample encoded text where the username is "username" and password is "password" separated by a ":"
        byte[] decode = null;
        String decodedText = null;
        String[] decodedArray = null;
        try {
            decode = Base64.getDecoder().decode(authorization.split("Basic ")[1]);
            decodedText = new String(decode);
            decodedArray = decodedText.split(":");
        } catch (IllegalArgumentException e) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        } catch (ArrayIndexOutOfBoundsException aexp) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }

        CustomerAuthEntity custAuthToken = customerService.authenticate(decodedArray[0], decodedArray[1]);
        CustomerEntity user = custAuthToken.getCustomer();
        LoginResponse authorizedCustomerResponse = new LoginResponse().id(user.getUuid()).
                message(SIGNIN_MESSAGE).
                firstName(user.getFirstName()).
                lastName(user.getLastName()).
                emailAddress(user.getEmail()).
                contactNumber(user.getContactNumber());
        HttpHeaders headers = new HttpHeaders();
        headers.add("access-token", custAuthToken.getAccessToken());
        return new ResponseEntity<>(authorizedCustomerResponse, headers, HttpStatus.OK);
    }

}
