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
1. Homepage con catalogo prodotti 3D
2. Chatbot AI integrato
3. Form contatti con honeypot anti-bot
4. Sistema registrazione utenti
5. **Area Admin:**
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
- [ ] Testare sistema AI preventivi (dopo deploy)
- [ ] Aggiungere catalogo completo prodotti aziende
- [ ] Cambiare email a spallanzanirappresentanze@gmail.com
- [ ] Acquistare dominio personalizzato

## Contatti
- Email: spallanzanirappresentanze@gmail.com
- Zona: Emilia Romagna (Modena e provincia)

## Note
- Il sito resta online su Render anche se spegni la VM
- Per modificare: clona da GitHub, modifica, push
- Render fa auto-deploy ad ogni push su main
