#!/usr/bin/bash

## TGT Req
nice -10 ../b/ccnxKRB_Client a ivan ccnx:/localhost

## CGT Req
nice -10 ../b/ccnxKRB_Client t ivan ccnx:/localhost ccnx:/localhost/uci/edu/fileA

## KRB-CCN Content Req
nice -10 ../b/ccnxKRB_Client k ivan ccnx:/localhost ccnx:/localhost/uci/edu/fileA

## Regular Content Req
nice -10 ../b/ccnxKRB_Client p content

