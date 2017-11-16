errf <- function(array){

    object <- 1.64*sd(array)/sqrt(length(array))

    return(object)
}

tgt = t(read.csv("tgt_rtt.csv", sep=" ", head=F))
tgt = tgt[-nrow(tgt),]
cgt = t(read.csv("cgt_rtt.csv", sep=" ", head=F))
cgt = cgt[-nrow(cgt),]
krb = t(read.csv("krb_rtt.csv", sep=" ", head=F))
krb = krb[-nrow(krb),]
reg = t(read.csv("reg_rtt.csv", sep=" ", head=F))
reg = reg[-nrow(reg),]

TGT = colMeans(tgt)
CGT = colMeans(cgt)
KRB = colMeans(krb)
REG = colMeans(reg)

errTGT = apply(tgt,2,errf)
errCGT = apply(cgt,2,errf)
errKRB = apply(krb,2,errf)
errREG = apply(reg,2,errf)

degrees = seq(from=300, to=3000, by=300)

#print(TGT)
#print(CGT)
#print(KRB)
#print(REG)

print(errTGT)
print(errCGT)
print(errKRB)
print(errREG)

means = c(rbind(TGT, CGT, KRB, REG))
errs = c(rbind(errTGT, errCGT, errKRB, errREG))

data = data.frame(rbind(TGT, CGT, KRB, REG))

pdf("bar.pdf")

barCenters <- barplot(as.matrix(data), main="Avg. per request RTT",
  xlab="Simultaneous Requests", col=c("darkblue","red","darkgreen","gold"),
  beside = TRUE,
  names.arg=degrees,
  ylab = "Avg. RTT (us)",
  ylim =c(0,1000000),
  cex.lab=1, cex.axis=1, cex.main=1, cex.sub=1, cex.names=0.9
)

arrows(barCenters, means - errs, barCenters,
       means + errs, lwd = 1.5, angle = 90,
       code = 3, length = 0.05)

legend("topleft", c("TGT", "CGT", "KRB", "REG"), fill = c("darkblue","red","darkgreen","gold"))
grid(10,10)
dev.off()
