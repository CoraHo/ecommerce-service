package com.coraho.ecommerceservice.controller;

import com.coraho.ecommerceservice.entity.Quote;
import com.coraho.ecommerceservice.service.QuoteService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/quotes")
public class QuoteController {
    private final QuoteService quoteService;

    public QuoteController(QuoteService quoteService) {
        this.quoteService = quoteService;
    }

    @GetMapping("/{quoteNumber}")
    public ResponseEntity<Quote> getQuoteByQuoteNumber(@PathVariable String quoteNumber) {
        return ResponseEntity.ok(quoteService.findByQuoteNumber(quoteNumber));
    }

    @GetMapping("/")
    public ResponseEntity<List<Quote>> getQuoteByCustomerId(@RequestParam Long customerId) {
        return ResponseEntity.ok(quoteService.findByCustomerId(customerId));
    }

    @PostMapping
    public ResponseEntity<Quote> addQuote(@RequestBody Quote quote) {
        return ResponseEntity.ok(quoteService.addQuote(quote));
    }

    @PutMapping("/{quoteNumber}")
    public ResponseEntity<Quote> updateQuoteStatus(@PathVariable String quoteNumber, @RequestBody Quote quote) {
        return ResponseEntity.ok(quoteService.updateQuoteStatus(quoteNumber, quote));
    }
}
