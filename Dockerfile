FROM node:erbium-alpine
ENV NODE_ENV uat
ENV PORT 3000
WORKDIR /usr/src/app
COPY ./ /usr/src/app/
RUN npm install --production
EXPOSE 3000
CMD ["sh", "-c", "date ; npm start "]