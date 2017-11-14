#!/usr/bin/bash

## TGT Req
../b/ccnxKRB_Client a ivan ccnx:/localhost

## CGT Req
../b/ccnxKRB_Client t ivan ccnx:/localhost ccnx:/localhost/uci/edu/fileA

## Content Req
../b/ccnxKRB_Client k ivan ccnx:/localhost ccnx:/localhost/uci/edu/fileA


