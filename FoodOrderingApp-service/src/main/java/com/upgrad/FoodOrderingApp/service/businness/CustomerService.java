package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.util.EmailValidator;
import com.upgrad.FoodOrderingApp.service.util.PasswordValidator;
import com.upgrad.FoodOrderingApp.service.util.PhoneValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;

@Service
public class CustomerService {

    @Autowired
    private PasswordCryptographyProvider cryptographyProvider;

    @Autowired
    CustomerDao customerDao;

    private static final String EMAIL_PATTERN = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
            + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

    /**
     * Service method to save customer data in database.
     *
     * @param customerEntity customer entity data to be stored.
     * @return saved customer entity data
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity saveCustomer(CustomerEntity customerEntity) throws SignUpRestrictedException {
        CustomerEntity contactumberExists = customerDao.checkContactNumber(customerEntity.getContactNumber());
        if (contactumberExists != null && contactumberExists.getContactNumber().equals(customerEntity.getContactNumber())) {
            throw new SignUpRestrictedException("SGR-001", "This contact number is already registered! Try other contact number.");
        }

        //validate password
        validatePassword(customerEntity);
        //add encrypted password and salt values
        String[] encryptedText = cryptographyProvider.encrypt(customerEntity.getPassword());
        customerEntity.setSalt(encryptedText[0]);
        customerEntity.setPassword(encryptedText[1]);
        //validate all fields are filled other than lastname before sending it to database.
        validateFields(customerEntity);
        //validate email id
        validateEmailid(customerEntity);
        //validate phone Number
        validatePhoneNumber(customerEntity);
        return customerDao.createUser(customerEntity);
    }


    /**
     * Helper method to validate password
     *
     * @param customerEntity entity object with password
     * @throws SignUpRestrictedException
     */
    private void validatePassword(CustomerEntity customerEntity) throws SignUpRestrictedException {
        PasswordValidator validator = new PasswordValidator();
        boolean validate = validator.validate(customerEntity.getPassword());
        if (!validate) {
            throw new SignUpRestrictedException("SGR-004", "Weak password!");
        }
    }

    /**
     * Helper method to validate phone Number
     *
     * @param customerEntity customerEntity with phone number
     */
    private void validatePhoneNumber(CustomerEntity customerEntity) throws SignUpRestrictedException {
        PhoneValidator phoneValidator = new PhoneValidator();
        boolean validPhonNumbere = phoneValidator.validate(customerEntity.getContactNumber());
        if (!validPhonNumbere) {
            throw new SignUpRestrictedException("SGR-003", "Invalid contact number!");
        }
    }

    /**
     * Helper method to validate email id
     *
     * @param customerEntity
     */
    private void validateEmailid(CustomerEntity customerEntity) throws SignUpRestrictedException {
        EmailValidator emailValidator = new EmailValidator();
        boolean validEmailId = emailValidator.validate(customerEntity.getEmail());
        if (!validEmailId) {
            throw new SignUpRestrictedException("SGR-002", "Invalid email-id format!");
        }
    }

    /**
     * Helper method to validate all fields in CustomerEntity are filled except lastName as that is allowed.
     *
     * @param customerEntity entiry object
     * @throws SignUpRestrictedException exception
     */
    private void validateFields(CustomerEntity customerEntity) throws SignUpRestrictedException {
        if (customerEntity.getUuid() != null && customerEntity.getUuid().trim().isEmpty() ||
                customerEntity.getContactNumber() != null && customerEntity.getContactNumber().trim().isEmpty() ||
                customerEntity.getEmail() != null && customerEntity.getEmail().trim().isEmpty() ||
                customerEntity.getFirstName() != null && customerEntity.getFirstName().trim().isEmpty() ||
                customerEntity.getPassword() != null && customerEntity.getPassword().trim().isEmpty()) {
            throw new SignUpRestrictedException("SGR-005", "Except last name all fields should be filled");
        }
    }

    public Object getCustomer(String database_accesstoken2) {
        return null;
    }

    /**
     * method used for authenticating the customer credentials.
     *
     * @param contactNumber contact number of the customer
     * @param password      password of the customer
     * @return CutomerAuthEntity with the auth token
     * @throws AuthenticationFailedException exception
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerAuthEntity authenticate(String contactNumber, String password) throws AuthenticationFailedException {
        CustomerEntity contactumberExists = customerDao.checkContactNumber(contactNumber);
        if (contactumberExists == null) {
            throw new AuthenticationFailedException("ATH-001", "This contact number has not been registered!");
        }
        CustomerEntity passwordRight = customerDao.checkPasswordisCorrect(contactNumber, password);

        String encryptedPwd = cryptographyProvider.encrypt(password, contactumberExists.getSalt());
        if (encryptedPwd.equals(contactumberExists.getPassword())) {
            JwtTokenProvider tokenProvider = new JwtTokenProvider(encryptedPwd);
            CustomerAuthEntity authEntity = new CustomerAuthEntity();
            authEntity.setCustomer(contactumberExists);
            final ZonedDateTime now = ZonedDateTime.now();
            final ZonedDateTime expiresAt = now.plusHours(8);
            authEntity.setAccessToken(tokenProvider.generateToken(contactumberExists.getUuid(), now, expiresAt));
            authEntity.setLoginAt(now);
            authEntity.setExpiresAt(expiresAt);
            authEntity.setUuid(contactumberExists.getUuid());
            customerDao.createAuthToken(authEntity);
            authEntity.setLogoutAt(null);
            return authEntity;
        } else {
            throw new AuthenticationFailedException("(ATH-002", "Invalid Credentials");
        }
    }
}
