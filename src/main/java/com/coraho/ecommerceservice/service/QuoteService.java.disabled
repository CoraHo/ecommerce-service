package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Customer;
import com.coraho.ecommerceservice.entity.Quote;
import com.coraho.ecommerceservice.entity.QuoteItem;
import com.coraho.ecommerceservice.repository.CustomerRepository;
import com.coraho.ecommerceservice.repository.QuoteRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class QuoteService {
    private final QuoteRepository quoteRepository;
    private final CustomerRepository customerRepository;

    public QuoteService(QuoteRepository quoteRepository, CustomerRepository customerRepository) {
        this.quoteRepository = quoteRepository;
        this.customerRepository = customerRepository;
    }

    public Quote findByQuoteNumber(String quoteNumber) {
        return quoteRepository.findByQuoteNumber(quoteNumber).orElseThrow(() -> new RuntimeException("Quote not found by Quote Number: " + quoteNumber));
    }

    public List<Quote> findByCustomerId(Long customerId) {
        if (!customerRepository.existsById(customerId)) {
            throw new RuntimeException("Customer not found by ID: " + customerId);
        }
        return quoteRepository.findByCustomerId(customerId);
    }

    public Quote addQuote(Quote quote) {
        Customer customer = quote.getCustomer();

        // 1. verify the customer email and name exist
        if (customer == null || customer.getEmail() == null || customer.getName() == null) {
            throw new IllegalArgumentException("Customer E-mail and Name must be provided.");
        }

        // 2. get or add a new customer
        Customer existingCustomer = customerRepository.findByEmail(customer.getEmail()).orElseGet(() -> {
            Customer newCustomer = Customer.builder().email(customer.getEmail()).name(customer.getName())
                            .phone(customer.getPhone()).address(customer.getAddress()).build();
            return customerRepository.save(newCustomer);
        });

        quote.setCustomer(existingCustomer);

        // 3. always assign a new quote number to the quote when no quote number provided
        quote.setQuoteNumber("Q-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase());

        // 4. Link quote items properly (Because of the CascadeType.ALL, each quote item will be inserted into quote_items table)
        if (quote.getItems() != null) {
            quote.getItems().forEach(item -> item.setQuote(quote));
        }

        return quoteRepository.save(quote);
    }

    public Quote updateQuoteStatus(String quoteNumber, Quote quote) {
        Quote existing = findByQuoteNumber(quoteNumber);
        existing.setStatus(quote.getStatus());
        return quoteRepository.save(existing);
    }
}
