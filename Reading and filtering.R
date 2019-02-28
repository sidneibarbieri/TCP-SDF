############################################################################################################
# Filtrar IP e TCP
# sudo tcpdump 'ip' and 'tcp' -r sample2.pcap -w tcpsample2.pcap

# Fragmentar em 500 arquivos de 10 MB
# sudo tcpdump 'ip' and 'tcp' -C 10 -W 500  -r 201806081400.pcap -w tcpf201806081400f

# Reunir os fragmentos de arquivos 
# mergecap -w sample2.pcap S0*

############################################################################################################
#==========Packages==========#
#install.packages("readr")
#install.packages("stringr")
#install.packages("tidyr")
#install.packages("dplyr")
#install.packages("ggplot2")
#install.packages("class")
#install.packages("shiny")
############################################################################################################
#==========Library==========#
library(C50)
library(caret) 
library(class)
library(corrplot)
library(data.table)
library(dplyr)
library(e1071)
library(foreign)
library(ggplot2)
library(gmodels)
library(magrittr)
library(partykit)
library(readr)
library(ROCR) 
library(rpart.plot) 
library(rpart)
library(shiny)
library(stringr)
library(tidyr)
############################################################################################################
#Conversão de PCAP em CSV
# tshark -T fields -E header=y -E separator=, -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e tcp.srcport -e _ws.col.Destination -e tcp.dstport -e _ws.col.Protocol -e _ws.col.Length -e _ws.col.Info -r sample2.pcap -E quote=s -E occurrence=f > sample2.csv
############################################################################################################
# experimentos individuais
# pacotes de probing #ACK_Scan.csv ou Probing TCP.csv 
file1 <- read.table(file="/Users/sidneibarbieri/Desktop/Projeto v_07/_Entrada CSV/Probing TCP.csv", header=TRUE, sep=",")  


# pacotes de not probing
file2 <- read.table(file="/Users/sidneibarbieri/Desktop/Projeto v_07/_Entrada CSV/ML_Sample2.csv", header=TRUE, sep=",")  

############################################################################################################
#df1
df1 <- as_data_frame(file1)
colnames(df1) <- c("No.", "Time", "Source", "Src.port", "Destination", "Dst.port", "Protocol", "Length", "Info")
df1$Info <- as.character(df1$Info)
df1$Info <- str_replace_all(df1$Info, "\342\206\222", ">")

df1$Probe <- TRUE



#TCP
df1 <- df1 %>%
  select(No., Source, Src.port, Destination, Dst.port, Protocol, Length, Probe, Info)  %>%
  filter(Protocol == "TCP")   %>% 
  filter(Source == "192.168.1.135" | Destination == "192.168.1.135") %>% #(Evitar endereços perdidos no probing) 
  filter(Source != "192.168.1.139" | Destination != "192.168.1.139")  


#df2
df2 <- as_data_frame(file2)
colnames(df2) <- c("No.", "Time", "Source", "Src.port", "Destination", "Dst.port", "Protocol", "Length", "Info")
df2$Info <- as.character(df2$Info)
df2$Info <- str_replace_all(df2$Info, "\342\206\222", ">")

df2$Probe <- FALSE


#TCP
df2 <- df2 %>%
  select(No., Source, Src.port, Destination, Dst.port, Protocol, Length, Probe, Info)  %>%
  filter(Protocol == "TCP")

############################################################################################################
# Construindo o dataframe
df <- rbind.data.frame(df1, df2)
head(df)
tail(df)
df <- df[order(df$No., decreasing=FALSE),]
dim(df1)
dim(df2)
dim(df)
table(df$Probe)

############################################################################################################
############################################################################################################

tcpdf <- df %>%
  select(Source, Src.port, Destination, Dst.port, Length, Probe, Info)

dim(tcpdf)
table(df$Probe)
############################################################################################################
############################################################################################################
# Mensagens
#	[Malformed Packet]
tcpdf$mfp <- as.character(tcpdf$Info)
tcpdf$mfp <- str_replace_all(tcpdf$mfp, "\\[Malformed Packet\\]", "MF=TRUE ")
tcpdf <- separate(tcpdf, mfp, c("x", "mfp"), sep = "MF=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, mfp, c("mfp", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$mfp <- str_replace_all(tcpdf$mfp, " ", "")
tcpdf$mfp <- ifelse(is.na(tcpdf$mfp), FALSE, ifelse(tcpdf$mfp == "TRUE", TRUE, "ERROR"))
tcpdf$mfp <- as.logical(tcpdf$mfp)

#	[TCP ACKed unseen segment]
tcpdf$unseen <- as.character(tcpdf$Info)
tcpdf$unseen <- str_replace_all(tcpdf$unseen, "\\[TCP ACKed unseen segment\\]", "unseen=TRUE ")
tcpdf <- separate(tcpdf, unseen, c("x", "unseen"), sep = "unseen=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, unseen, c("unseen", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$unseen <- str_replace_all(tcpdf$unseen, " ", "")
tcpdf$unseen <- ifelse(is.na(tcpdf$unseen), FALSE, ifelse(tcpdf$unseen == "TRUE", TRUE, "ERROR"))
tcpdf$unseen <- as.logical(tcpdf$unseen)

#	[TCP Dup ACK 96650#14]
tcpdf$DupACK <- as.character(tcpdf$Info)
tcpdf$DupACK <- str_replace_all(tcpdf$DupACK, "\\[TCP Dup ACK ", "DupACK=TRUE ")
tcpdf <- separate(tcpdf, DupACK, c("x", "DupACK"), sep = "DupACK=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, DupACK, c("DupACK", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$DupACK <- str_replace_all(tcpdf$DupACK, " ", "")
tcpdf$DupACK <- ifelse(is.na(tcpdf$DupACK), FALSE, ifelse(tcpdf$DupACK == "TRUE", TRUE, "ERROR"))
tcpdf$DupACK <- as.logical(tcpdf$DupACK)

#	[TCP Fast Retransmission]
tcpdf$FastRet <- as.character(tcpdf$Info)
tcpdf$FastRet <- str_replace_all(tcpdf$FastRet, "\\[TCP Fast Retransmission\\]", "FastRet=TRUE ")
tcpdf <- separate(tcpdf, FastRet, c("x", "FastRet"), sep = "FastRet=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, FastRet, c("FastRet", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$FastRet <- str_replace_all(tcpdf$FastRet, " ", "")
tcpdf$FastRet <- ifelse(is.na(tcpdf$FastRet), FALSE, ifelse(tcpdf$FastRet == "TRUE", TRUE, "ERROR"))
tcpdf$FastRet <- as.logical(tcpdf$FastRet)

#	[TCP Keep-Alive]
tcpdf$KeepAl <- as.character(tcpdf$Info)
tcpdf$KeepAl <- str_replace_all(tcpdf$KeepAl, "\\[TCP Keep-Alive\\]", "KeepAl=TRUE ")
tcpdf <- separate(tcpdf, KeepAl, c("x", "KeepAl"), sep = "KeepAl=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, KeepAl, c("KeepAl", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$KeepAl <- str_replace_all(tcpdf$KeepAl, " ", "")
tcpdf$KeepAl <- ifelse(is.na(tcpdf$KeepAl), FALSE, ifelse(tcpdf$KeepAl == "TRUE", TRUE, "ERROR"))
tcpdf$KeepAl <- as.logical(tcpdf$KeepAl)

#	[TCP Keep-Alive ACK]
tcpdf$KeepAlACK <- as.character(tcpdf$Info)
tcpdf$KeepAlACK <- str_replace_all(tcpdf$KeepAlACK, "\\[TCP Keep-Alive ACK\\]", "KeepAlACK=TRUE ")
tcpdf <- separate(tcpdf, KeepAlACK, c("x", "KeepAlACK"), sep = "KeepAlACK=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, KeepAlACK, c("KeepAlACK", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$KeepAlACK <- str_replace_all(tcpdf$KeepAlACK, " ", "")
tcpdf$KeepAlACK <- ifelse(is.na(tcpdf$KeepAlACK), FALSE, ifelse(tcpdf$KeepAlACK == "TRUE", TRUE, "ERROR"))
tcpdf$KeepAlACK <- as.logical(tcpdf$KeepAlACK)

#	[TCP Out-Of-Order]
tcpdf$OutOrd <- as.character(tcpdf$Info)
tcpdf$OutOrd <- str_replace_all(tcpdf$OutOrd, "\\[TCP Out-Of-Order\\]", "OutOrd=TRUE ")
tcpdf <- separate(tcpdf, OutOrd, c("x", "OutOrd"), sep = "OutOrd=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, OutOrd, c("OutOrd", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$OutOrd <- str_replace_all(tcpdf$OutOrd, " ", "")
tcpdf$OutOrd <- ifelse(is.na(tcpdf$OutOrd), FALSE, ifelse(tcpdf$OutOrd == "TRUE", TRUE, "ERROR"))
tcpdf$OutOrd <- as.logical(tcpdf$OutOrd)

#[Packet size limited during capture] 
tcpdf$PSizeL <- as.character(tcpdf$Info)
tcpdf$PSizeL <- str_replace_all(tcpdf$PSizeL, "\\[Packet size limited during capture\\]", "PSizeL=TRUE ")
tcpdf <- separate(tcpdf, PSizeL, c("x", "PSizeL"), sep = "PSizeL=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, PSizeL, c("PSizeL", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$PSizeL <- str_replace_all(tcpdf$PSizeL, " ", "")
tcpdf$PSizeL <- ifelse(is.na(tcpdf$PSizeL), FALSE, ifelse(tcpdf$PSizeL == "TRUE", TRUE, "ERROR"))
tcpdf$PSizeL <- as.logical(tcpdf$PSizeL)

#	[TCP Port numbers reused]
tcpdf$PNReused <- as.character(tcpdf$Info)
tcpdf$PNReused <- str_replace_all(tcpdf$PNReused, "\\[TCP Port numbers reused\\]", "PNReused=TRUE ")
tcpdf <- separate(tcpdf, PNReused, c("x", "PNReused"), sep = "PNReused=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, PNReused, c("PNReused", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$PNReused <- str_replace_all(tcpdf$PNReused, " ", "")
tcpdf$PNReused <- ifelse(is.na(tcpdf$PNReused), FALSE, ifelse(tcpdf$PNReused == "TRUE", TRUE, "ERROR"))
tcpdf$PNReused <- as.logical(tcpdf$PNReused)

#	[TCP Previous segment not captured]
tcpdf$PSNCapt <- as.character(tcpdf$Info)
tcpdf$PSNCapt <- str_replace_all(tcpdf$PSNCapt, "\\[TCP Previous segment not captured\\]", "PSNCapt=TRUE ")
tcpdf <- separate(tcpdf, PSNCapt, c("x", "PSNCapt"), sep = "PSNCapt=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, PSNCapt, c("PSNCapt", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$PSNCapt <- str_replace_all(tcpdf$PSNCapt, " ", "")
tcpdf$PSNCapt <- ifelse(is.na(tcpdf$PSNCapt), FALSE, ifelse(tcpdf$PSNCapt == "TRUE", TRUE, "ERROR"))
tcpdf$PSNCapt <- as.logical(tcpdf$PSNCapt)

#	[TCP Retransmission]
tcpdf$Retrans <- as.character(tcpdf$Info)
tcpdf$Retrans <- str_replace_all(tcpdf$Retrans, "\\[TCP Retransmission\\]", "Retrans=TRUE ")
tcpdf <- separate(tcpdf, Retrans, c("x", "Retrans"), sep = "Retrans=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Retrans, c("Retrans", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$Retrans <- str_replace_all(tcpdf$Retrans, " ", "")
tcpdf$Retrans <- ifelse(is.na(tcpdf$Retrans), FALSE, ifelse(tcpdf$Retrans == "TRUE", TRUE, "ERROR"))
tcpdf$Retrans <- as.logical(tcpdf$Retrans)

#	[TCP segment of a reassembled PDU]
tcpdf$ReassPDU <- as.character(tcpdf$Info)
tcpdf$ReassPDU <- str_replace_all(tcpdf$ReassPDU, "\\[TCP segment of a reassembled PDU\\]", "ReassPDU=TRUE ")
tcpdf <- separate(tcpdf, ReassPDU, c("x", "ReassPDU"), sep = "ReassPDU=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, ReassPDU, c("ReassPDU", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$ReassPDU <- str_replace_all(tcpdf$ReassPDU, " ", "")
tcpdf$ReassPDU <- ifelse(is.na(tcpdf$ReassPDU), FALSE, ifelse(tcpdf$ReassPDU == "TRUE", TRUE, "ERROR"))
tcpdf$ReassPDU <- as.logical(tcpdf$ReassPDU)

#	[TCP Spurious Retransmission]
tcpdf$Spurious <- as.character(tcpdf$Info)
tcpdf$Spurious <- str_replace_all(tcpdf$Spurious, "\\[TCP Spurious Retransmission\\]", "Spurious=TRUE ")
tcpdf <- separate(tcpdf, Spurious, c("x", "Spurious"), sep = "Spurious=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Spurious, c("Spurious", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$Spurious <- str_replace_all(tcpdf$Spurious, " ", "")
tcpdf$Spurious <- ifelse(is.na(tcpdf$Spurious), FALSE, ifelse(tcpdf$Spurious == "TRUE", TRUE, "ERROR"))
tcpdf$Spurious <- as.logical(tcpdf$Spurious)

#	[TCP Window Update]
tcpdf$WinUp <- as.character(tcpdf$Info)
tcpdf$WinUp <- str_replace_all(tcpdf$WinUp, "\\[TCP Window Update\\]", "WinUp=TRUE ")
tcpdf <- separate(tcpdf, WinUp, c("x", "WinUp"), sep = "WinUp=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, WinUp, c("WinUp", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$WinUp <- str_replace_all(tcpdf$WinUp, " ", "")
tcpdf$WinUp <- ifelse(is.na(tcpdf$WinUp), FALSE, ifelse(tcpdf$WinUp == "TRUE", TRUE, "ERROR"))
tcpdf$WinUp <- as.logical(tcpdf$WinUp)

#	[TCP Window Full]
tcpdf$WFull <- as.character(tcpdf$Info)
tcpdf$WFull <- str_replace_all(tcpdf$WFull, "\\[TCP Window Full\\]", "WFull=TRUE ")
tcpdf <- separate(tcpdf, WFull, c("x", "WFull"), sep = "WFull=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, WFull, c("WFull", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$WFull <- str_replace_all(tcpdf$WFull, " ", "")
tcpdf$WFull <- ifelse(is.na(tcpdf$WFull), FALSE, ifelse(tcpdf$WFull == "TRUE", TRUE, "ERROR"))
tcpdf$WFull <- as.logical(tcpdf$WFull)

#	[TCP ZeroWindow]
tcpdf$ZeroWin <- as.character(tcpdf$Info)
tcpdf$ZeroWin <- str_replace_all(tcpdf$ZeroWin, "\\[TCP ZeroWindow\\]", "ZeroWin=TRUE ")
tcpdf <- separate(tcpdf, ZeroWin, c("x", "ZeroWin"), sep = "ZeroWin=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, ZeroWin, c("ZeroWin", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$ZeroWin <- str_replace_all(tcpdf$ZeroWin, " ", "")
tcpdf$ZeroWin <- ifelse(is.na(tcpdf$ZeroWin), FALSE, ifelse(tcpdf$ZeroWin == "TRUE", TRUE, "ERROR"))
tcpdf$ZeroWin <- as.logical(tcpdf$ZeroWin)

############################################################################################################
# Sequência
# 0, 1, 2, 3, 4, None (0 pq Wireshark relativiza)
tcpdf$Seq <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, Seq, c("x", "Seq"), sep = "Seq=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Seq, c("Seq", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$SeqC <- as.numeric(tcpdf$Seq) # Categorizando
tcpdf$SeqC <- ifelse(is.na(tcpdf$SeqC), "NONE", ifelse(tcpdf$SeqC == 0, "ZERO", 
                                                       ifelse(tcpdf$SeqC == 1, "ONE", 
                                                              ifelse(tcpdf$SeqC == 2, "TWO", 
                                                                     ifelse(tcpdf$SeqC == 3, "THREE", 
                                                                            ifelse(tcpdf$SeqC == 4, "FOUR",
                                                                                   ifelse(tcpdf$SeqC == 5, "FIVE",
                                                                                          ifelse(tcpdf$SeqC > 5, "POSIT", "ERROR"))))))))
tcpdf$Seq <- as.numeric(tcpdf$Seq)
tcpdf$SeqC <- as.factor(tcpdf$SeqC)

# Ack
# Zero, Um, Positivo, None
tcpdf$Ack <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, Ack, c("x", "Ack"), sep = "Ack=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Ack, c("Ack", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$AckC <- as.numeric(tcpdf$Ack) # Categorizando
tcpdf$AckC <- ifelse(is.na(tcpdf$AckC), "NONE", ifelse(tcpdf$AckC == 0, "ZERO", 
                                                       ifelse(tcpdf$AckC == 1, "ONE", 
                                                              ifelse(tcpdf$AckC == 2, "TWO", 
                                                                     ifelse(tcpdf$AckC == 3, "THREE", 
                                                                            ifelse(tcpdf$AckC == 4, "FOUR",
                                                                                   ifelse(tcpdf$AckC == 5, "FIVE",
                                                                                          ifelse(tcpdf$AckC > 5, "POSIT", "ERROR"))))))))
tcpdf$Ack <- as.numeric(tcpdf$Ack) 
tcpdf$AckC <- as.factor(tcpdf$AckC)

############################################################################################################
# Win
tcpdf$Win <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, Win, c("x", "Win"), sep = "Win=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Win, c("Win", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Win, c("Win", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$Win <- as.numeric(tcpdf$Win)

# Win Categórico
# Zero ou Positivo
tcpdf$WinC <- tcpdf$Win
tcpdf$WinC <- ifelse(is.na(tcpdf$WinC), "NONE", ifelse(tcpdf$WinC == 0, "ZERO", 
                                                       ifelse(tcpdf$WinC == 1, "ONE", 
                                                              ifelse(tcpdf$WinC == 2, "TWO", 
                                                                     ifelse(tcpdf$WinC == 3, "THREE", 
                                                                            ifelse(tcpdf$WinC == 4, "FOUR",
                                                                                   ifelse(tcpdf$WinC == 5, "FIVE",
                                                                                          ifelse(tcpdf$WinC > 5, "POSIT", "ERROR"))))))))
tcpdf$WinC <- as.factor(tcpdf$WinC)

############################################################################################################
# Urg
tcpdf$Urg <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, Urg, c("x", "Urg"), sep = "Urg=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Urg, c("Urg", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Urg, c("Urg", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$Urg <- as.numeric(tcpdf$Urg)

# Urg Categórico
# Zero ou Positivo
tcpdf$UrgC <- tcpdf$Urg
tcpdf$UrgC <- ifelse(is.na(tcpdf$UrgC), "NONE", ifelse(tcpdf$UrgC == 0, "ZERO",
                                                       ifelse(tcpdf$UrgC > 0, "POSIT", "ERROR")))
tcpdf$UrgC <- as.factor(tcpdf$UrgC)

############################################################################################################
# WS
tcpdf$WS <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, WS, c("x", "WS"), sep = "WS=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, WS, c("WS", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, WS, c("WS", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$WS <- as.numeric(tcpdf$WS)

# WS Categórico
# Zero ou Positivo
tcpdf$WSC <- tcpdf$WS
tcpdf$WSC <- ifelse(is.na(tcpdf$WSC), "NONE", ifelse(tcpdf$WSC == 0, "ZERO",
                                                     ifelse(tcpdf$WSC == 1, "ONE",
                                                            ifelse(tcpdf$WSC > 1, "POSIT", "ERROR"))))
tcpdf$WinC <- as.factor(tcpdf$WinC)

############################################################################################################
# Len
tcpdf$Len <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, Len, c("x", "Len"), sep = "Len=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Len, c("Len", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Len, c("Len", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$Len <- as.integer(tcpdf$Len)

# Len Categórico
# Zero ou Positivo
tcpdf$LenC <- tcpdf$Len
tcpdf$LenC <- ifelse(is.na(tcpdf$LenC), "NONE", ifelse(tcpdf$LenC == 0, "ZERO",
                                                       ifelse(tcpdf$LenC > 0, "POSIT", "ERROR")))
tcpdf$LenC <- as.factor(tcpdf$LenC)

############################################################################################################
# MSS
tcpdf$MSS <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, MSS, c("x", "MSS"), sep = "MSS=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, MSS, c("MSS", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, MSS, c("MSS", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$MSS <- as.numeric(tcpdf$MSS)

# MSS Categórico
# Zero ou Positivo
tcpdf$MSSC <- as.numeric(tcpdf$MSS)
tcpdf$MSSC <- ifelse(is.na(tcpdf$MSSC), "NONE", ifelse(tcpdf$MSSC == 0, "ZERO", 
                                                       ifelse(tcpdf$MSSC == 1, "ONE", 
                                                              ifelse(tcpdf$MSSC == 2, "TWO", 
                                                                     ifelse(tcpdf$MSSC == 3, "THREE", 
                                                                            ifelse(tcpdf$MSSC == 4, "FOUR",
                                                                                   ifelse(tcpdf$MSSC == 5, "FIVE",
                                                                                          ifelse(tcpdf$MSSC > 5, "POSIT", "ERROR"))))))))
tcpdf$MSSC <- as.factor(tcpdf$MSSC)



############################################################################################################
# SACK_PERM
tcpdf$SACK_PERM <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, SACK_PERM, c("x", "SACK_PERM"), sep = "SACK_PERM=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, SACK_PERM, c("SACK_PERM", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, SACK_PERM, c("SACK_PERM", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$SACK_PERM <- as.numeric(tcpdf$SACK_PERM)
tcpdf$SACK_PERM <- ifelse(is.na(tcpdf$SACK_PERM), FALSE, ifelse(tcpdf$SACK_PERM == 1, TRUE, "ERROR"))
tcpdf$SACK_PERM <- as.logical(tcpdf$SACK_PERM)

############################################################################################################
# TSval
tcpdf$TSval <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, TSval, c("x", "TSval"), sep = "TSval=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, TSval, c("TSval", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, TSval, c("TSval", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$TSval <- as.numeric(tcpdf$TSval)

# TSval Categórico
# None, Zero, Um ou Positivo
tcpdf$TSvalC <- tcpdf$TSval
tcpdf$TSvalC <- ifelse(is.na(tcpdf$TSvalC), "NONE", ifelse(tcpdf$TSvalC == 0, "ZERO",
                                                           ifelse(tcpdf$TSvalC == 1, "ONE",
                                                                  ifelse(tcpdf$TSvalC > 1, "POSIT", "ERROR"))))

############################################################################################################
# TSecr
tcpdf$TSecr <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, TSecr, c("x", "TSecr"), sep = "TSecr=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, TSecr, c("TSecr", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, TSecr, c("TSecr", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$TSecr <- as.numeric(tcpdf$TSecr)

# TSecr Categórico
# None, Zero, Um ou Positivo
tcpdf$TSecrC <- tcpdf$TSecr
tcpdf$TSecrC <- ifelse(is.na(tcpdf$TSecrC), "NONE", ifelse(tcpdf$TSecrC == 0, "ZERO",
                                                           ifelse(tcpdf$TSecrC == 1, "ONE",
                                                                  ifelse(tcpdf$TSecrC > 1, "POSIT", "ERROR"))))



############################################################################################################
# Flags
tcpdf$Flag <- as.character(tcpdf$Info)
tcpdf <- separate(tcpdf, Flag, c("Flag", "x"), sep = "\\] Seq", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Flag, c("y", "Flag"), sep = " \\[", remove = TRUE, convert = FALSE)

# Organização das Flags 

#"URG", "ACK", "PSH", "RST", "SYN", "FIN"
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "<None>", " None=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "URG", " URG=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "ACK", " ACK=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "PSH", " PSH=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "RST", " RST=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "SYN", " SYN=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "FIN", " FIN=1 ")
# Firewalls
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "NS", " NS=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "Reserved", " Reserved=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "ECN", " ECN=1 ")
tcpdf$Flag <- str_replace_all(tcpdf$Flag, "CWR", " CWR=1 ")

#=========== None
tcpdf$None <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, None, c("x", "None"), sep = "None=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, None, c("None", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$None <- ifelse(is.na(tcpdf$None), FALSE, ifelse(tcpdf$None == 1, TRUE, "ERROR"))
#=========== URG
tcpdf$URG <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, URG, c("x", "URG"), sep = "URG=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, URG, c("URG", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$URG <- ifelse(is.na(tcpdf$URG), FALSE, ifelse(tcpdf$URG == 1, TRUE, "ERROR"))
#=========== ACK
tcpdf$ACK <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, ACK, c("x", "ACK"), sep = "ACK=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, ACK, c("ACK", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$ACK <- ifelse(is.na(tcpdf$ACK), FALSE, ifelse(tcpdf$ACK == 1, TRUE, "ERROR"))
#=========== PSH
tcpdf$PSH <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, PSH, c("x", "PSH"), sep = "PSH=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, PSH, c("PSH", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$PSH <- ifelse(is.na(tcpdf$PSH), FALSE, ifelse(tcpdf$PSH == 1, TRUE, "ERROR"))
#=========== RST
tcpdf$RST <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, RST, c("x", "RST"), sep = "RST=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, RST, c("RST", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$RST <- ifelse(is.na(tcpdf$RST), FALSE, ifelse(tcpdf$RST == 1, TRUE, "ERROR"))
#=========== SYN
tcpdf$SYN <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, SYN, c("x", "SYN"), sep = "SYN=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, SYN, c("SYN", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$SYN <- ifelse(is.na(tcpdf$SYN), FALSE, ifelse(tcpdf$SYN == 1, TRUE, "ERROR"))
#=========== FIN
tcpdf$FIN <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, FIN, c("x", "FIN"), sep = "FIN=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, FIN, c("FIN", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$FIN <- ifelse(is.na(tcpdf$FIN), FALSE, ifelse(tcpdf$FIN == 1, TRUE, "ERROR"))
#=========== NS
tcpdf$NS <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, NS, c("x", "NS"), sep = "NS=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, NS, c("NS", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$NS <- ifelse(is.na(tcpdf$NS), FALSE, ifelse(tcpdf$NS == 1, TRUE, "ERROR"))
#=========== Reserved
tcpdf$Reserved <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, Reserved, c("x", "Reserved"), sep = "Reserved=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, Reserved, c("Reserved", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$Reserved <- ifelse(is.na(tcpdf$Reserved), FALSE, ifelse(tcpdf$Reserved == 1, TRUE, "ERROR"))
#=========== ECN
tcpdf$ECN <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, ECN, c("x", "ECN"), sep = "ECN=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, ECN, c("ECN", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$ECN <- ifelse(is.na(tcpdf$ECN), FALSE, ifelse(tcpdf$ECN == 1, TRUE, "ERROR"))
#=========== CWR
tcpdf$CWR <- as.character(tcpdf$Flag)
tcpdf <- separate(tcpdf, CWR, c("x", "CWR"), sep = "CWR=", remove = TRUE, convert = FALSE)
tcpdf <- separate(tcpdf, CWR, c("CWR", "y"), sep = " ", remove = TRUE, convert = FALSE)
tcpdf$CWR <- ifelse(is.na(tcpdf$CWR), FALSE, ifelse(tcpdf$CWR == 1, TRUE, "ERROR"))

############################################################################################################
# DifLen (Diferença entre o comprimento do pacote e do payload)
tcpdf$Length <- as.integer(tcpdf$Length) 
tcpdf$Len <- as.integer(tcpdf$Len) 
tcpdf$Length[is.na(tcpdf$Length)] <- 0
tcpdf$Len[is.na(tcpdf$Len)] <- 0
tcpdf$DifLen <- (tcpdf$Length - tcpdf$Len)
tcpdf$DifLen <- as.integer(tcpdf$DifLen) 
tcpdf$DifLen[is.na(tcpdf$DifLen)] <- 0

# DifLenC
tcpdf$DifLenC <- as.integer(tcpdf$DifLen) 
#tcpdf$DifLenC <- ifelse((tcpdf$DifLen >= 54) & (tcpdf$DifLen <= 134), TRUE, FALSE)
tcpdf$DifLenC <- ifelse((tcpdf$DifLen == 54), TRUE, 
                        ifelse((tcpdf$DifLen == 58), TRUE, 
                               ifelse((tcpdf$DifLen == 62), TRUE, 
                                      ifelse((tcpdf$DifLen == 66), TRUE, 
                                             ifelse((tcpdf$DifLen == 70), TRUE, 
                                                    ifelse((tcpdf$DifLen == 74), TRUE, 
                                                           ifelse((tcpdf$DifLen == 78), TRUE, 
                                                                  ifelse((tcpdf$DifLen == 82), TRUE, 
                                                                         ifelse((tcpdf$DifLen == 86), TRUE, 
                                                                                ifelse((tcpdf$DifLen == 90), TRUE, 
                                                                                       ifelse((tcpdf$DifLen == 94), TRUE, 
                                                                                              ifelse((tcpdf$DifLen == 98), TRUE, 
                                                                                                     ifelse((tcpdf$DifLen == 102), TRUE, 
                                                                                                            ifelse((tcpdf$DifLen == 106), TRUE, 
                                                                                                                   ifelse((tcpdf$DifLen == 110), TRUE, 
                                                                                                                          ifelse((tcpdf$DifLen == 114), TRUE, 
                                                                                                                                 ifelse((tcpdf$DifLen == 118), TRUE, 
                                                                                                                                        ifelse((tcpdf$DifLen == 122), TRUE, 
                                                                                                                                               ifelse((tcpdf$DifLen == 126), TRUE, 
                                                                                                                                                      ifelse((tcpdf$DifLen == 130), TRUE, 
                                                                                                                                                             ifelse((tcpdf$DifLen == 134), TRUE, FALSE)))))))))))))))))))))
tcpdf$DifLenC <- as.logical(tcpdf$DifLenC)

############################################################################################################
# Src.port Categórico e Dst.port Categórico (Well Known Ports (0-1023), as Registered Ports (1024-49151) e rivate Ports (49152-65535))
tcpdf$Src.portC <- tcpdf$Src.port
tcpdf$Dst.portC <- tcpdf$Dst.port

tcpdf$Src.portC <- ifelse(is.na(tcpdf$Src.portC), "NONE", ifelse(tcpdf$Src.portC < 1024, "WKP", ifelse(tcpdf$Src.portC < 49152, "REG", "PRIV")))
tcpdf$Dst.portC <- ifelse(is.na(tcpdf$Dst.portC), "NONE", ifelse(tcpdf$Dst.portC < 1024, "WKP", ifelse(tcpdf$Dst.portC < 49152, "REG", "PRIV")))

tcpdf$Src.portC <- as.factor(tcpdf$Src.portC)
tcpdf$Dst.portC <- as.factor(tcpdf$Dst.portC)

############################################################################################################
# Selecionar features de interesse
tcpdf <- tcpdf %>%
  select(Probe, 
         Source, 
         Src.port, 
         Src.portC,
         Destination, 
         Dst.port, 
         Dst.portC, 
         Length, 
         URG, ACK, PSH, RST, SYN, FIN, NS, Reserved, ECN, CWR, 
         Seq, 
         SeqC, 
         Ack, 
         AckC, 
         Win, 
         WinC,
         Urg, 
         UrgC,
         Len, 
         LenC,
         DifLen, 
         DifLenC,
         MSS, 
         MSSC,
         SACK_PERM, 
         TSval, 
         TSvalC, 
         TSecr, 
         TSecrC, 
         WS, 
         WSC,
         mfp, 	 #	[Malformed Packet]	
         unseen, 	 #	[TCP ACKed unseen segment]	
         DupACK, 	 #	[TCP Dup ACK XXXXXX#XX]	
         FastRet, 	 #	[TCP Fast Retransmission]	
         KeepAl, 	 #	[TCP Keep-Alive]	
         KeepAlACK, 	 #	[TCP Keep-Alive ACK]	
         OutOrd, 	 #	[TCP Out-Of-Order]	
         PSizeL, 	 #	[Packet size limited during capture]	
         PNReused, 	 #	[TCP Port numbers reused]	
         PSNCapt, 	 #	[TCP Previous segment not captured]	
         Retrans, 	 #	[TCP Retransmission]	
         WFull,      # [TCP Window Full]
         ReassPDU, 	 #	[TCP segment of a reassembled PDU]	
         Spurious, 	 #	[TCP Spurious Retransmission]	
         WinUp, 	 #	[TCP Window Update]	
         ZeroWin) 	 #	[TCP ZeroWindow]	

############################################################################################################
# Remover NA's
tcpdf[is.na(tcpdf)] <- 0
############################################################################################################
tcpdffull <- tcpdf
# Filtrar Seq Grande para Trafego Normal
tcpdf <- subset(tcpdf, (Probe==FALSE & Seq <= 20) | 
                  (Probe == FALSE & Ack <= 20) | 
                  (Probe == TRUE) | 
                  (URG == TRUE) | 
                  ## (ACK == TRUE) | é utilizado na transmissão de dados
                  (RST == TRUE) | 
                  (SYN == TRUE) | 
                  (FIN == TRUE) | 
                  (NS == TRUE) | 
                  (Reserved == TRUE) | 
                  (ECN == TRUE)| 
                  (CWR == TRUE))


# Randomizar a ordem
set.seed(234)
tcpdf <- tcpdf[sample(1:nrow(tcpdf)), ]

############################################################################################################
## Aplicação de Filtros
############################################################################################################
inicio <- Sys.time()
# Aplicando Rule A
tcpdfR1 <- subset(tcpdf, (DifLenC == TRUE) | (DifLenC == FALSE & ACK == FALSE) | Length > 134 )  #justificar

# Aplicando Rule B
tcpdfR2 <- subset(tcpdfR1, (DifLenC == TRUE) | (MSSC == "NONE") | (Win %% 64 != 0))  #justificar

# Aplicando Rule C
tcpdfR3 <- subset(tcpdfR2, (!(URG == TRUE | PSH == TRUE | RST == TRUE | FIN == TRUE) & (DifLenC == FALSE)) | (DifLenC == TRUE))  #justificar (URG == TRUE | PSH == TRUE | RST == TRUE | FIN == TRUE) & (DifLenC == FALSE)

fim <- Sys.time()
tempo <- (fim - inicio)
tempo
############################################################################################################
#tcpdffull
table(tcpdffull$Probe)
table(tcpdf$Probe)
table(tcpdfR1$Probe)
table(tcpdfR2$Probe)
table(tcpdfR3$Probe)

# Gravar dados
#write.csv2(tcpdf, file="/Users/sidneibarbieri/Desktop/Projeto v_07/_Saída CSV/exp4.csv") # df
#write.csv(tcpdf, file="/Users/sidneibarbieri/Desktop/Projeto v_07/_Saída CSV/weka_exp4.csv") #weka
############################################################################################################