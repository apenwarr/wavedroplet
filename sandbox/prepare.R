filename = "imaginary.data"

data = read.table(file = filename, header = T, sep = ",")
length(data[is.na(data$seq), ])

pairs = data.frame(unique(data[c("ta", "ra")]))
pairs$num = c(1:length(pairs))

data$pair_num = NA

# I hate this workaround but the proper way doesn't work: should be
# data[data$ta == as.character(pairs$ta) & data$ra == as.character(pairs$ra),"pair_num"] = pairs$num
# but complains about the length. I don't know how to make R happy here.

ordinal = 1;
for (pair in pairs) {
  data[  data$ta == as.character(pair[1])
                & data$ra == as.character(pair[2])
               ,"pair_num"] = ordinal;
  ordinal = ordinal + 1;
}

write.table(
  data,
  file=paste(filename, ".prepared", sep=""),
  sep=",",
  quote=F,
  na="",
  row.names=F);

