# Sorbonne Université 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : BELAREF Nail, 3521025
# Etudiant.e 2 : 0
import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR =[0.09213414037491088,  0.010354463742221126,  0.030178915678726964,  0.03753683726285317,  0.17174710607479665,  0.010939030914707838,  0.01061497737343803,  0.010717912027723734,  0.07507240372750529,  0.003832727374391129,  6.989390105819367e-05,  0.061368115927295096,  0.026498684088462805,  0.07030818127173859,  0.049140495636714375,  0.023697844853330825,  0.010160031617459242,  0.06609294363882899,  0.07816806814528274,  0.07374314880919855,  0.06356151362232132,  0.01645048271269667,  1.14371838095226e-05,  0.004071637436190045,  0.0023001447439151006,  0.0012263202640210343]


#chiffrement César
def chiffre_cesar(txt, key):
    """
    parcourir le text par lettre et renvoyer un text 
    chiffré avec key décalage
    @param txt, key
    @return text chiffré
    """
    index = key
    message_chiffre=""
    for lettre in txt:
    #print(chr((ord(lettre) + index)%26+65))
        lettre_chiffre=chr((ord(lettre) -65 + index)%26+65)
        message_chiffre=message_chiffre + lettre_chiffre
    #print(message_chiffre)
    return message_chiffre


# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    rendre le resultat de chiffrement cesar avec l'inverse de la clé 
    @param txt, key
    @return key
    """
    clef_cesar = -(key)%26
    return chiffre_cesar(txt, clef_cesar)

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    parcourir le text et appliquer le chiffrement cesar
    sur chaque lettre avec la cle correspendante dans key
    @param txt, cle
    @return txt_chiffre
    """
    i=0
    txt_chiffre=""
    for lettre in txt:
        txt_chiffre= txt_chiffre + chiffre_cesar(lettre, key[i%len(key)])
        i= i+1
    return txt_chiffre

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    inverser toute les clefs pour obtenir un nouveau tableau de cle
    avec lequel on appel la fonction vigenere pour avoir le text claire
    @param txt, key
    @return txt_déchiffrer
    """
    new_key= [((-i)%26) for i in key]
#   print(new_key)
    return chiffre_vigenere(txt, new_key)

# Analyse de fréquences
def freq(txt):
    """
    parcourir le text, recuperer l'indice de la lettre(variable de boucle) depuis
    l'alphabet, incrementer la valeur de cette indice dans hist
    @param txt
    @return hist #tableau de frequence
    """
    hist=[0.0]*len(alphabet)
    indice=0
    for lettre in txt:
        indice = alphabet.index(lettre)
        hist[indice]= hist[indice]+1.0

    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    parcourir le text et incrementer en parallele une liste de fréquence 
    par rapport à la position de la lettre dans l'alphabet
    @param text
    @return indice de la lettre la plus frequente
    """
    return freq(txt).index(max(freq(txt)))

# indice de coïncidence
def indice_coincidence(hist):
    """
    retourne la somme de freqence de chaque lettre sur la longuer du text
    @param hist, frequence des lettres d'un text
    @return indice de coincidence
    """
    somme=0
    for i in range(len(alphabet)):
        d = hist[i]*(hist[i]-1)
        somme+=d
    #print(somme/(sum(hist)*(sum(hist)-1)))
    return somme/(sum(hist)*(sum(hist)-1))

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    parcourir deux boucles imbriquées, sommer les indices de coincidences
    de chaque colonnes et l'ajouter dans un tableau. enfin parcourir
    le tableau et renvoyer l'indice+1 de la premiere occurence de valeur >0.06
    @param cipher
    @return longueur 
    """
    ic = []
    ic_count=0
    for taille in range(1,21):
        for i in range(0, taille):
            ic_count+=indice_coincidence(freq(cipher[i:len(cipher):taille]))
        ic.append(ic_count/taille)
        #print(taille," ", ic_count/taille)
        ic_count=0
    #print(ic)
    for e in ic:
        if e>0.06:
           # print(ic.index(e)+1)
            return ic.index(e)+1
    return 0
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    Réordonner le text en colonnes allant de 0 à key_length(colonnes) 
    chercher la lettre la plus frequente à chaque fois
    Soustraire l'indice de la lettre la plus frequente en alphabet
    @param key_length
    @return decalage #tableau de décalage pour lettre de la cle
    
    """
    decalages=[0]*key_length
    for col in range(key_length):
        d=lettre_freq_max(cipher[col:len(cipher):key_length])-freq_FR.index(max(freq_FR))
        #print(d%26)
        decalages[col]=d%26
    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    retourne text dechiffré après avoir trouvé la longueur de la clef 
    ensuite la clef (tableau de décalage)
    @param cipher
    @return decipher
    """
    key_length=longueur_clef(cipher)
    clef=clef_par_decalages(cipher, key_length)
   
    return dechiffre_vigenere(cipher,clef)


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    retourne l'indice de concidence mutuelle de h1 et h2, ce dernier décallé
    de d
    @param h1, h2, d #(h1, h2) frequence de lettre de deux text
    @return ICM
    """
   
    h2_d=[h2[(i+d)%len(h2)] for i in range(0, len(h2))]
    somme=0
    for x, y in zip(h1,h2_d):
        somme+=(x*y)

    return somme/(sum(h1)*sum(h2))

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Renvoie le tableau des décalages probables étant
    donné la longueur de la clé
    en comparant l'indice de décalage mutuel par rapport
    à la première colonne
    @param cipher, key_length
    @return decalage #tableau de decalage correspandant au ICM maximum entre la premiere
                     #colonne et i-eme colonne(i compris entre 0 et longueur clef)
    """
    icm_tab=[]
    decalages=[0]*key_length
    colonne_1=freq(cipher[0:len(cipher):key_length])
    for i in range(key_length):
        #d=0
        colonne_i=freq(cipher[i:len(cipher):key_length])
        for j in range(0, len(alphabet)):
                       icm=indice_coincidence_mutuelle(colonne_1,colonne_i, j)
                       icm_tab.append(icm)
        decalages[i]=icm_tab.index(max(icm_tab))
        icm_tab=[]            
    #print(decalages)
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    retourner le text déchiffré 
    """
    key_length = longueur_clef(cipher)
    deca = tableau_decalages_ICM(cipher, key_length)
    text_cesar=dechiffre_vigenere(cipher, deca)
    text_clair=""
    freq_max=lettre_freq_max(text_cesar)
    mon_decalage=(freq_FR.index(max(freq_FR))-freq_max)%26
    text_clair=chiffre_cesar(text_cesar, mon_decalage)
    return text_clair


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
from math import sqrt
def Var(X):
    somme=sum(X)
    moyenne = somme/len(X)
    var=0
    for e in X:
        var+=(e-moyenne)**2
    return var/(len(X)-1)

def Cov(X, Y):
    sommeX=sum(X)
    sommeY=sum(Y)
    moyenneX=sommeX/len(X)
    moyenneY=sommeY/len(Y)
    cov=0
    for ex, ey in zip(X,Y):
        cov+=(ex-moyenneX)*(ey-moyenneY)
    return cov/(len(X)-1)

def correlation(L1,L2):
    """
    retourne la correlation: cor(X,Y) = Cov(X,Y)/sqrt(Var(X))*sqrt(Var(Y))
    """
    cor = Cov(L1,L2)/(sqrt(Var(L1))*sqrt(Var(L2)))
    return cor
# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée

def clef_correlations(cipher, key_length):
    """
    retourne la moyenne des correlations maximale entre freq_FR et i-eme colonne (i allant
    de 0 à key_length), la clef 
    @param cipher, key_length
    @return moyenne des correlation maximales, clef 
    """
    
    key=[]
    cor_max=[]
    score = 0.0
    i =0
    while(i<key_length):
        l = []
        for j in range(26):
            l.append(correlation(freq_FR, freq(dechiffre_cesar(cipher[i::key_length],j))))
        cor_max.append(max(l))
        key.append(l.index(max(l)))
        i+=1
    score=sum(cor_max)/key_length
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    retourne text dechiffré
    @param cipher
    @return decipher
    """
    key_length=longueur_clef(cipher)
    score, key= clef_correlations(cipher, key_length)
    text= dechiffre_vigenere(cipher, key)
    return text
################   Réponses_aux_questions   ####################################################
# CryptAnalyse V1:
# ==> 18 texts successfully unciphered.
# ==> caracteristique de ceux qui echouent: longueur de la clé importante
# ==> explications: les texts ne sont pas assez long alors les colonnes
#                  produit lors de calcul d'indice mutuel sont courts pour une analyse
#                  frequentielle, donc ça fournit moins d'information sur les décalages
#
# CryptAnalyse V2:
# ===> 43 texts successfully unciphered.
# ===> caracteristique des texts qui echouent: longueur de cle assez grande pour des texts courts
# ===> explications: le nombre de texts déchiffrés augmente car on a changé la methode de
#                   cryptanalyse frequentielle par une cryptanalyse avec l'indice de
#                   coincidence mutuel. toutefois le nombre des texts qui échouent est toujours
#                   superieur à 50% car d'un point de vu theorique, la methode de ICM
#                   nécessite une taille de text assez longue pour pouvoir négliger l'erreur.
#
# Cryptanalyse V3:
# ===> 84 texts successfully unciphered.
# ===> caracteristique des texts qui echouent: texts un peu trop courts pour une analyse correcte
# ===> explications: notre cryptanalyse n'est pas rentable lorsque le text est court et la clef
#      tres longue donc le rapport de corrélation n'est pas significatif pour ces exemples
#
#################################################################################################

################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
