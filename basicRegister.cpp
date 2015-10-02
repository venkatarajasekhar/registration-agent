#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "resip/stack/ExtensionHeader.hpp"
#include "resip/stack/HeaderTypes.hpp"
#include "resip/stack/SipMessage.hpp"
#include "resip/stack/SipStack.hpp"
#include "resip/dum/ClientAuthManager.hpp"
#include "resip/dum/ClientRegistration.hpp"
#include "resip/dum/DialogUsageManager.hpp"
#include "resip/dum/MasterProfile.hpp"
#include "resip/dum/RegistrationHandler.hpp"
#include "rutil/Log.hpp"
#include "rutil/Logger.hpp"
#include "rutil/ServerProcess.hpp"
#include "rutil/Subsystem.hpp"
#include "resip/dum/KeepAliveManager.hpp"

#if defined (USE_SSL)
#if defined(WIN32) 
#include "resip/stack/ssl/WinSecurity.hpp"
#else
#include "resip/stack/ssl/Security.hpp"
#endif
#endif

#ifndef WIN32
#include <signal.h>
#endif

#include "RegConfig.hpp"

#define RESIPROCATE_SUBSYSTEM Subsystem::TEST

#define DEFAULT_CONFIG_FILE "basicRegister.config"

using namespace resip;
using namespace std;

class ClientHandler : public ClientRegistrationHandler
{
   public:
      ClientHandler() : done(false) {}

      virtual void onSuccess(ClientRegistrationHandle h, const SipMessage& response)
      {
         InfoLog( << "ClientHandler::onSuccess: " << endl );
      }

      virtual void onRemoved(ClientRegistrationHandle, const SipMessage& response)
      {
         InfoLog ( << "ClientHandler::onRemoved ");
         done = true;
      }

      virtual void onFailure(ClientRegistrationHandle, const SipMessage& response)
      {
         InfoLog ( << "ClientHandler::onFailure - check the configuration.  Peer response: " << response );
      }

      virtual int onRequestRetry(ClientRegistrationHandle, int retrySeconds, const SipMessage& response)
      {
         WarningLog ( << "ClientHandler:onRequestRetry, want to retry immediately");
         return 0;
      }
      
      bool done;
};

static void
signalHandler(int signo)
{
#ifndef WIN32
   if(signo == SIGHUP)
   {
      InfoLog(<<"Received HUP signal, logger reset");
      try{
      Log::reset();
      }catch(...){
         
      }
      return;
   }
#endif
   WarningLog(<<"Unexpected signal, ignoring it: " << signo);
}

class MyClientRegistrationAgent : public ServerProcess
{
   public:
      MyClientRegistrationAgent() {};
      ~MyClientRegistrationAgent() {};

      void run(int argc, char **argv)
      {
         try{
         Data defaultConfigFile(DEFAULT_CONFIG_FILE); //Ctor
         }catch(...){
            
         }
         try{
         RegConfig cfg;
         }catch(...){
            
         }
         try
         {
            cfg.parseConfig(argc, argv, defaultConfigFile);
         }
         catch(BaseException& ex)
         {
            std::cerr << "Error parsing configuration: " << ex << std::endl;
            syslog(LOG_DAEMON | LOG_CRIT, "%s", ex.getMessage().c_str());
            exit(1);
         }
         try{
         setPidFile(cfg.getConfigData("PidFile", "", true));
         }catch(...){
            
         }
         if(cfg.getConfigBool("Daemonize", false))
         {
            daemonize();
         }
         try{
         Data loggingType(cfg.getConfigData("LoggingType", "cout", true));
         }catch(...){
            
         }
         try{
         Data logLevel (cfg.getConfigData("LogLevel", "INFO", true));
         }catch(...){
            
         }
         try{
         Data logFilename (cfg.getConfigData("LogFilename", "basicRegister.log", true));
         }catch(...){
            
         }
         try{
         Log::initialize(loggingType, logLevel, argv[0], logFilename.c_str(), 0);
         }catch(...){
            
         }
#ifndef WIN32
         if ( signal( SIGHUP, signalHandler ) == SIG_ERR )
         {
            ErrLog(<<"Couldn't install signal handler for SIGHUP");
            exit(-1);
         }
#endif

         InfoLog(<<"Starting client registration agent");

         NameAddr userAor(cfg.getConfigData("UserAor", "", false));
         try{
         Data passwd(cfg.getConfigData("Password", "", false));  //ctor
         }catch(...){
            
         }

#ifdef USE_SSL
#ifdef WIN32
         try{
         Security* security = new WinSecurity;
         }catch(...){
            
         }
#else
         try{
         Security* security = new Security;
         }catch(...){
            
         }
         security->addCADirectory(cfg.getConfigData("CADirectory", "/etc/ssl/certs", true));
#endif
         try{
         SipStack stack(security);
         }catch(...){
            
         }
#else
         try{
         SipStack stack;
         }catch(...){
            
         }
#endif
         try{ 
         DialogUsageManager clientDum(stack);
         }catch(...){
            
         }
         SharedPtr<MasterProfile> profile(new MasterProfile);
         auto_ptr<ClientAuthManager> clientAuth(new ClientAuthManager);
         ClientHandler clientHandler;

         // stack.addTransport(UDP, 0, V4);
         // stack.addTransport(UDP, 0, V6);
         stack.addTransport(TCP, 0, V4);
         // stack.addTransport(TCP, 0, V6);
#ifdef USE_SSL
         // stack.addTransport(TLS, 0, V4);
         // stack.addTransport(TLS, 0, V6);
#endif
         clientDum.setMasterProfile(profile);
         clientDum.setClientRegistrationHandler(&clientHandler);
         clientDum.setClientAuthManager(clientAuth);
         clientDum.getMasterProfile()->setDefaultRegistrationTime(cfg.getConfigInt("RegistrationExpiry", 3600));
         // Retry every 60 seconds after a hard failure:
         clientDum.getMasterProfile()->setDefaultRegistrationRetryTime(60);

         // keep alive test.
         try{
         <KeepAliveManager> keepAlive(new KeepAliveManager);
         }catch(...){
            
         }
         try{
         clientDum.setKeepAliveManager(keepAlive);
         }catch(...){
         }

         clientDum.getMasterProfile()->setDefaultFrom(userAor);
         profile->setDigestCredential(userAor.uri().host(),
                                           userAor.uri().user(),
                                           passwd);

         profile->addSupportedOptionTag(Token(Symbols::Outbound));
         profile->addSupportedOptionTag(Token(Symbols::Path));
         try{
         Data outboundProxy(cfg.getConfigData("OutboundProxy", "", true));
         }catch(...){
            
         }
         if(!outboundProxy.empty())
         {
            const Uri _outboundProxy(outboundProxy);
            profile->setOutboundProxy(_outboundProxy);
         }
         try{ 
         <SipMessage> regMessage; 
         }catch(...){
            
         }
         try{
         clientDum.makeRegistration(userAor);
         }catch(...){
            
         }
         try{
         NameAddr contact(cfg.getConfigData("Contact", "", false));
         }catch(...){
            
         }
         try{
         contact.param(p_regid);
         }catch(...){
            
         }
         try{
            contact.param(p_Instance);
         }catch(...){
            
         }
         try{
         regMessage->header(h_Contacts).clear();
         }catch(...){
            
         }
         try{
         regMessage->header(h_Contacts).push_back(contact);
         }catch(...){
            
         }
         try{
         clientDum.send( regMessage );
         }catch(...){
            
         }

         int n = 0;
         while ( true )
         {
            stack.process(100);
            while(clientDum.process());
         }
       }
};
MyClientRegistrationAgent::MyClientRegistrationAgent(){
   
}

MyClientRegistrationAgent ::~MyClientRegistrationAgent() {
   
}

int
main(int argc, char** argv)
{
   MyClientRegistrationAgent agent;
   try{
   agent.run(argc, argv);
   }catch(...){
      
   }
}

/* ====================================================================
 * The Vovida Software License, Version 1.0 
 * 
 * Copyright (c) 2000 Vovida Networks, Inc.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * 3. The names "VOCAL", "Vovida Open Communication Application Library",
 *    and "Vovida Open Communication Application Library (VOCAL)" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact vocal@vovida.org.
 *
 * 4. Products derived from this software may not be called "VOCAL", nor
 *    may "VOCAL" appear in their name, without prior written
 *    permission of Vovida Networks, Inc.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL VOVIDA
 * NETWORKS, INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT DAMAGES
 * IN EXCESS OF $1,000, NOR FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * 
 * ====================================================================
 * 
 * This software consists of voluntary contributions made by Vovida
 * Networks, Inc. and many individuals on behalf of Vovida Networks,
 * Inc.  For more information on Vovida Networks, Inc., please see
 * <http://www.vovida.org/>.
 *
 */
