# SPALLANZANI RAPPRESENTANZE - INFO PROGETTO

## Descrizione
Sito web per Spallanzani Rappresentanze - azienda che rappresenta marchi di porte, serramenti e maniglie in Emilia Romagna.

## Aziende Rappresentate
- **Flessya** - Porte per interni (Nidio, Kikka, Vetra)
- **Di.Bi.** - Porte blindate (classe 3, 4, 5)
- **Arieni** - Maniglie di design (ottone, acciaio)
- **Mondocasa**
- **Eproditalia**

## Stack Tecnico
- **Backend:** Flask (Python)
- **Database:** SQLite
- **Hosting:** Render.com (free tier)
- **AI:** Google Gemini 2.5 Flash API
- **Email:** Gmail SMTP

## URL Produzione
- **Sito:** https://spallanzani-serramenti.onrender.com
- **Admin:** https://spallanzani-serramenti.onrender.com/admin
- **GitHub:** https://github.com/fabiospall/spallanzani-serramenti

## Credenziali Admin
| Utente | Username | Password |
|--------|----------|----------|
| Fabio | fabio | fabio2024! |
| Papà | papa | papa2024! |
| Mamma | mamma | mamma2024! |

## Environment Variables (Render)
- `GEMINI_API_KEY`: AIzaSyDQS7Q8iSuw3gDCakWmUCyrYdQb9MSKZwM
- `EMAIL_PASSWORD`: wleftxurgzatzadc (app password Gmail)

## Email Configurata
- **Attuale (test):** fabiospalla31@gmail.com
- **Definitiva:** spallanzanirappresentanze@gmail.com

## Funzionalità Implementate
1. Homepage con catalogo prodotti 3D interattivo
2. **Chatbot AI con Gemini** - Risposte intelligenti su tutti i brand
3. Form contatti con honeypot anti-bot
4. Sistema registrazione utenti
5. **Filtri prodotti per brand** - Ricerca rapida per categoria
6. **38 prodotti totali:**
   - 10 porte Flessya
   - 10 porte blindate Di.Bi.
   - 6 maniglie Arieni
   - 6 serramenti PVC Mondocasa (NUOVO)
   - 6 infissi alluminio Eproditalia (NUOVO)
7. **Area Admin:**
   - Login sicuro con anti-brute force (5 tentativi max, blocco 30 min)
   - Dashboard preventivi
   - Generazione preventivi con Gemini AI
   - Invio email automatico con conferma
   - Visualizzazione richieste dal sito

## Sicurezza Implementata
- Protezione SSTI (Server-Side Template Injection)
- Protezione XSS
- Rate limiting
- Rilevamento scanner (Nmap, Nikto, etc.)
- Security headers (X-Frame-Options, CSP, etc.)
- Honeypot anti-bot
- Anti-brute force su login admin
- Input sanitization

## TODO Rimanenti
- [x] Aggiungere catalogo completo prodotti Mondocasa
- [x] Aggiungere catalogo completo prodotti Eproditalia
- [x] Chatbot AI con Gemini integrato
- [x] Sistema filtri prodotti per brand
- [ ] Testare sistema AI preventivi (dopo deploy)
- [ ] Cambiare email a spallanzanirappresentanze@gmail.com
- [ ] Acquistare dominio personalizzato
- [ ] Aggiungere sezione recensioni/testimonianze (opzionale)
- [ ] Sostituire immagini placeholder con foto ufficiali brand

## Contatti
- Email: spallanzanirappresentanze@gmail.com
- Zona: Emilia Romagna (Modena e provincia)

## Note
- Il sito resta online su Render anche se spegni la VM
- Per modificare: clona da GitHub, modifica, push
- Render fa auto-deploy ad ogni push su main
