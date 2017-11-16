errf <- function(array){

    object <- 1.64*sd(array)/sqrt(length(array))

    return(object)
}

tgt = t(read.csv("all_cached_thput.csv", sep=" ", head=F))
tgt = tgt[-nrow(tgt),]
cgt = t(read.csv("no_cached_thput.csv", sep=" ", head=F))
cgt = cgt[-nrow(cgt),]
krb = t(read.csv("tgt_cached_thput.csv", sep=" ", head=F))
krb = krb[-nrow(krb),]
reg = t(read.csv("reg_req_thput.csv", sep=" ", head=F))
reg = reg[-nrow(reg),]

TGT = colMeans(tgt)/1000000
CGT = colMeans(cgt)/1000000
KRB = colMeans(krb)/1000000
REG = colMeans(reg)/1000000

errTGT = apply(tgt,2,errf)/1000000
errCGT = apply(cgt,2,errf)/1000000
errKRB = apply(krb,2,errf)/1000000
errREG = apply(reg,2,errf)/1000000

degrees = seq(from=200, to=2000, by=200)

#print(TGT)
#print(CGT)
#print(KRB)
#print(REG)

print(errTGT)
print(errCGT)
print(errKRB)
print(errREG)

means = c(rbind(CGT, KRB, TGT))
errs = c(rbind(errCGT, errKRB, errTGT))

data = data.frame(rbind(CGT, KRB, TGT))

pdf("bar.pdf")

barCenters <- barplot(as.matrix(data), main="Client perceived content throughput",
  xlab="Interests per second", col=c("darkblue","red","darkgreen"),
  beside = TRUE,
  names.arg=degrees,
  ylab = "Throughput (Mbps)",
  ylim =c(0,150),
  cex.lab=1, cex.axis=1, cex.main=1, cex.sub=1, cex.names=0.9
)

arrows(barCenters, means - errs, barCenters,
       means + errs, lwd = 1.5, angle = 90,
       code = 3, length = 0.05)

abline(h=max(TGT), lwd=2,lty=2,col = "darkgreen")
abline(h=max(KRB), lwd=2,lty=2,col = "red")
abline(h=max(CGT), lwd=2,lty=2,col = "darkblue")

legend("topleft", c("No caching", "TGT caching only", "TGT+CGT caching"), fill = c("darkblue", "red","darkgreen"))
grid(10,10)
dev.off()
