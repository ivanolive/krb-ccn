
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

degrees = seq(from=300, to=3000, by=300)

print(TGT)
print(CGT)
print(KRB)
print(REG)

means = c(rbind(TGT, CGT, KRB, REG))
data = data.frame(rbind(TGT, CGT, KRB, REG))

png("bar.png")

barplot(as.matrix(data), main="Avg. per request RTT",
  xlab="Simultaneous Requests", col=c("darkblue","red","green","yellow"),
  beside = TRUE,
  names.arg=degrees,
  ylab = "Avg. RTT (us)",
  ylim =c(0,1000000)
)
legend("topleft", c("TGT", "CGT", "KRB", "REG"), fill = c("darkblue","red","green","yellow"))
dev.off()
