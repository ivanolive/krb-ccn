names = list.files(".")
print(names)
#names = c()
for (file in names){
  print(file)
#  name = paste("./time_names/",file,sep="")
#  names = c(names,name)
}

d1 = read.csv(names[1],head=F)$V1
d2 = read.csv(names[2],head=F)$V1
d3 = read.csv(names[3],head=F)$V1
#d4 = read.csv(names[4],head=F)$V1
#d5 = read.csv(names[5],head=F)$V1
#d6 = read.csv(names[6],head=F)$V1

pdf("times.pdf",height=5,width=10)
boxplot(d1,d2,d3,
        names= c("TGT-Producer","CGT-Producer","Content Producer"),
        outline=F,
        ylab = "Processing time [us]",
        xlab = "Algorithms of KRB-CCN Design",
        cex.lab=1.5, cex.axis=1.5, cex.main=1.5, cex.sub=1.5, cex.names=1
)
grid(nx=NA, ny=NULL, lwd=1, lty=2)

dev.off()
